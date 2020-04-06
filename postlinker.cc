#include "elf.h"
#include "utils.h"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unistd.h>

using headerT = Elf64_Ehdr;
using segmentT = Elf64_Phdr;
using sectionT = Elf64_Shdr;

using relaT = Elf64_Rela;
using relT = Elf64_Rel;
using symT = Elf64_Sym;

using std::vector;
using std::string;
using std::unordered_map;


typedef struct Context {
  int file_end;
  int base_address;
  int orig_start;
} Context;

template <typename T>
void readHeaders(FILE* fd, headerT& elfh, vector<T>& v, int count, int offset) {
  fseek(fd, offset, 0);
  for(int i = 0; i < count; ++i) {
    T tmp;
    fread((char *)&tmp, sizeof tmp, 1, fd);
    v.emplace_back(tmp);
  }
}

template <typename T>
void readSectionEntries(FILE* fd, sectionT& s, vector<T>& sections) {
  fseek(fd, s.sh_offset, 0);
  int count = s.sh_size / (sizeof(T));
  while (count) {
    T sec;
    fread((char*)&sec, sizeof sec, 1, fd);
    sections.emplace_back(sec);
    --count;
  }
}


void readStrings(FILE* fd, sectionT& s, vector<unordered_map<int, string>>& strings) {
  vector<char> raw_strings(s.sh_size);
  string tmp;
  unordered_map<int, string> section_strings;

  fseek(fd, s.sh_offset,0);
  fread((char*)raw_strings.data(), s.sh_size, 1, fd);
  int i = 0, index = 0;
  for (auto c : raw_strings) {
    if (c != '\0') {
      tmp += c;
    } else if (tmp.size()) {
      section_strings[index] = tmp;
      tmp = "";
      index = i + 1;
    }
    ++i;
  }
  if (section_strings.size()) {
    strings.emplace_back(section_strings);
  }
}

string& getSymbolName(symT symbol, vector<unordered_map<int, string>> strings) {
  for (auto& m : strings) {
    if (m.find(symbol.st_name) != m.end()) {
      return m[symbol.st_name];
    }
  }
}

bool correctSymbolType(unsigned int type) {
  return type == STT_NOTYPE || type == STT_FUNC || type == STT_OBJECT || type == STT_SECTION;
}

void findBaseAddress(Context& ctx, vector<segmentT>& segments) {
  int min = INT_MAX;
  for (auto& p : segments) {
    if (p.p_type == PT_LOAD && p.p_vaddr < min) {
      min = p.p_vaddr;
    }
  }
  ctx.base_address = min;
}

void makeSpaceForHeaders(Context& ctx, headerT& header,
                         vector<segmentT>& out_segments,
                         vector<segmentT>& exec_segments) {
  auto org_size = exec_segments.size();
  int size = 0;
  for (int i = org_size; i < out_segments.size(); ++i) {
    size += sizeof(segmentT);
  }
  size += constants::kPageSize - (size % constants::kPageSize);
  for (auto& p : out_segments) {
    if (p.p_vaddr == ctx.base_address) {
      p.p_paddr -= size;
      p.p_vaddr = p.p_paddr;
      ctx.base_address = p.p_paddr;
      p.p_memsz += constants::kPageSize;
      p.p_filesz += constants::kPageSize;
      break;
    }
  }
  out_segments[0].p_paddr = out_segments[0].p_vaddr -= size;
  for (auto& p : out_segments) {
    if (p.p_type != PT_PHDR && p.p_offset != 0) {
      p.p_offset += constants::kPageSize;
    }
  }
  auto end = out_segments[org_size - 1].p_offset + out_segments[org_size - 1].p_filesz;
  std::cout << "end : " << end << "\n";
  /* header.e_shoff = end + (constants::kPageSize - (end % constants::kPageSize)); */
  header.e_shoff = end;
}

void addNewSegment(Context& ctx, headerT& header,
                   vector<segmentT>& segments,
                   vector<sectionT>& sections,
                   vector<sectionT>& rel_sections,
                   int segment_flags) {
  if (sections.size()) {
    segmentT p;
    int size = 0;
    int new_off = ctx.file_end;

    /* std::cout << "new_off: " << new_off << "\n"; */
    /* std::cout << "sections_offset + size " << header.e_shoff + sizeof(sectionT) * header.e_shnum << "\n"; */
    if (new_off % constants::kPageSize != 0) {
      /* std::cout << "reszta: " << new_off % constants::kPageSize << "\n"; */
      new_off += constants::kPageSize - (new_off % constants::kPageSize);
    }
    /* std::cout << "new_off, po modulo: " << new_off << "\n"; */
    std::for_each(sections.begin(), sections.end(), [&](sectionT s) {
        for(auto& rel_s : rel_sections) {
          if (rel_s.sh_name == s.sh_name) {
            rel_s.sh_offset = new_off + size;
            break;
          }
        }
        if (size % s.sh_addralign != 0) {
          size += s.sh_addralign - (size % s.sh_addralign);
        };
        size += s.sh_size;
    });
    if (size != 0) {
      p.p_type = PT_LOAD;
      p.p_flags = segment_flags;
      p.p_offset = new_off;
      p.p_vaddr = new_off + ctx.base_address;
      p.p_paddr = new_off + ctx.base_address;
      p.p_filesz = size;
      p.p_memsz = size;
      p.p_align = constants::kPageSize;

      size += constants::kPageSize - (size % constants::kPageSize);
      ctx.file_end += size;
      segments.emplace_back(p);
      header.e_phnum++;
    }
  }
}

void applyRelocations(Context& ctx, FILE* rel, FILE* exec, FILE* output,
                      headerT& rel_header, headerT& exec_header,
                      vector<sectionT>& exec_sections,
                      vector<sectionT>& rel_sections) {
  vector<relT> rels;
  vector<relaT> relas;
  vector<symT> rel_syms, exec_syms;
  vector<unordered_map<int, string>> rel_strings, exec_strings;
  int section_id = 0;

  for (auto& s : rel_sections) {
    if (s.sh_type == SHT_STRTAB && section_id != rel_header.e_shstrndx) {
      readStrings(rel, s, rel_strings);
    } else if (s.sh_type == SHT_RELA) {
      readSectionEntries(rel, s, relas);
    } else if (s.sh_type == SHT_REL) {
      readSectionEntries(rel, s, rels);
    } else if (s.sh_type == SHT_SYMTAB) {
      readSectionEntries(rel, s, rel_syms);
    }
    ++section_id;
  }

  section_id = 0;
  for (auto& s : exec_sections) {
    if (s.sh_type == SHT_STRTAB && section_id != exec_header.e_shstrndx) {
      readStrings(exec, s, exec_strings);
    } else if (s.sh_type == SHT_SYMTAB) {
      readSectionEntries(exec, s, exec_syms);
    }
    ++section_id;
  }

  for (auto& r : relas) {
    int symbol_address;
    auto& symbol = rel_syms[ELF64_R_SYM(r.r_info)];
    auto sym_name = getSymbolName(symbol, rel_strings);
    if (correctSymbolType(ELF64_ST_TYPE(symbol.st_info))) {
      if (symbol.st_shndx == SHN_UNDEF) {
        for (auto& exec_s : exec_syms) {
          if (getSymbolName(exec_s, exec_strings) == sym_name) {
            symbol_address = exec_s.st_value;
            break;
          }
        }
      } else {
        if (sym_name == "orig_start") {
          symbol_address = ctx.orig_start;
        } else {
          auto section_offset = rel_sections[symbol.st_shndx].sh_offset;
          symbol_address = symbol.st_value + ctx.base_address;
        }
      }
      auto section_offset = rel_sections[symbol.st_shndx].sh_offset;
      auto instr_address = section_offset + r.r_offset + ctx.base_address;
      auto addend = r.r_addend;

      fseek(output, instr_address - ctx.base_address, 0);
      unsigned int r_type = ELF64_R_TYPE(r.r_info);
      if (isPCReference(r_type)) {
        unsigned int address = symbol_address + addend - instr_address;
        fwrite(&address, 1, sizeof(unsigned int), output);
      } else if (isAbsReference(r_type)) {
        unsigned int address = symbol_address + addend;
        fwrite(&address, 1, sizeof(unsigned int), output);
      }
    }
  }
}

void saveOutput(headerT& output_header, vector<segmentT>& output_segments,
                vector<sectionT>& output_sections, vector<vector<sectionT>>&& rel_sections,
                FILE* output, FILE* exec) {

  fseek(output, 0, 0);
  // Save header
  fwrite(&output_header, 1, sizeof(output_header), output);

  // Save segment headers
  fseek(output, output_header.e_phoff, 0);
  for (auto& p : output_segments) {
      fwrite(&p, 1, sizeof(segmentT), output);
  };

  /* // Save Sections */
  for (auto& s : output_sections) {
      vector<char> tmp(s.sh_size);
      fseek(exec, s.sh_offset, 0);
      fread((char*)tmp.data(), 1, s.sh_size, exec);
      int pos = ftell(output);
      if (s.sh_addralign != 0 && pos % s.sh_addralign != 0) {
        fseek(output, s.sh_addralign - (pos % s.sh_addralign), SEEK_CUR);
      }
      fwrite(tmp.data(), s.sh_size, sizeof(char), output);
  }

  // Saving section headers
  fseek(output, output_header.e_shoff, 0);
  std::cout << "saving under: " << output_header.e_shoff << "\n";
  int i = 0;
  for (auto& s : output_sections) {
    s.sh_offset = output_header.e_shoff + i * sizeof(sectionT);
    std::cout << "new offset " << s.sh_offset << "\n";
    fwrite(&s, 1, sizeof(sectionT), output);
    ++i;
  };

  // Saving rel sections
  for (auto& v : rel_sections) {
    auto pos = ftell(output);
    if (pos % constants::kPageSize == 0) {
      pos += constants::kPageSize - (pos % constants::kPageSize);
      fseek(output, pos, 0);
    }
    for (auto& s : v) {
      vector<char> tmp(s.sh_size);
      fseek(exec, s.sh_offset, 0);
      fread((char*)tmp.data(), s.sh_size, 1, exec);

      pos = ftell(output);
      if (s.sh_addralign != 0 && pos % s.sh_addralign == 0) {
        fseek(output, s.sh_addralign - (pos % s.sh_addralign), SEEK_CUR);
      }
      fwrite(tmp.data(), s.sh_size, sizeof(char), output);
    }
  }
  return;
}


int runPostlinker(FILE *exec, FILE *rel, FILE *output) {

  headerT exec_header, rel_header, out_header;
  vector<segmentT> exec_segments, output_segments;
  vector<sectionT> exec_sections, rel_sections, output_sections;
  Context ctx;

  /* vector<relaSectionT> rela_sections; */
  /* vector<symT> symbols; */



  // Executable
  fread((char *)&exec_header, sizeof exec_header, 1, exec);
  ctx.orig_start = exec_header.e_entry;

  readHeaders(exec, exec_header, exec_segments,
              exec_header.e_phnum, exec_header.e_phoff);
  readHeaders(exec, exec_header, exec_sections,
              exec_header.e_shnum, exec_header.e_shoff);
  fseek(exec, 0, SEEK_END);
  ctx.file_end = ftell(exec);
  /* std::cout << "Sections location: " <<ctx.file_end - exec_header.e_shnum * sizeof(sectionT) << "\n"; */
  findBaseAddress(ctx, exec_segments);

  out_header = exec_header;
  output_segments = exec_segments;
  output_sections = exec_sections;

  // Relocatable
  fread((char *)&rel_header, sizeof rel_header, 1, rel);
  readHeaders(rel, rel_header, rel_sections,
              rel_header.e_shnum, rel_header.e_shoff);


  vector<sectionT> RSections, RWSections, RXSections, RWXSections;

  for (auto& s : rel_sections) {
    if (s.sh_flags & SHF_ALLOC) {
      if ((s.sh_flags & SHF_EXECINSTR)
          && (s.sh_flags & SHF_WRITE)) {
        RWXSections.emplace_back(s);
      } else if (s.sh_flags & SHF_WRITE) {
        RWSections.emplace_back(s);
      } else if (s.sh_flags & SHF_EXECINSTR) {
        RXSections.emplace_back(s);
      } else {
        RSections.emplace_back(s);
      }
    }
  }

  addNewSegment(ctx, out_header, output_segments, RSections, rel_sections, constants::kR);
  addNewSegment(ctx, out_header, output_segments, RWSections, rel_sections, constants::kRW);
  addNewSegment(ctx, out_header, output_segments, RXSections, rel_sections, constants::kRX);
  addNewSegment(ctx, out_header, output_segments, RWXSections, rel_sections, constants::kRWX);
  makeSpaceForHeaders(ctx, out_header, output_segments, exec_segments);

  saveOutput(out_header, output_segments, output_sections,
             {RSections, RWSections, RXSections, RWXSections}, output, exec);
  /* applyRelocations(ctx, rel, exec, output, rel_header, out_header, exec_sections, rel_sections); */
  return 0;
}


int main() {

  // TODO(Change to argv)
  FILE *rel = fopen("z1-example/rel.o", "rb");
  if (!rel) {
    // TODO(Fix msg)
    LOG_ERROR("Failed to open file rel.o");
    return -1;
  }

  // TODO(Change to argv)
  FILE *exec = fopen("z1-example/exec-orig", "rb");
  if (!exec) {
    // TODO(Fix msg)
    LOG_ERROR("Failed to open file exec-orig.o");
    closeFiles(rel);
    return -1;
  }

  // TODO(Change to argv)
  FILE *output = fopen("z1-example/exec-bp", "w+");
  if (!output) {
    // TODO(Fix msg)
    LOG_ERROR("Failed to open file output");
    closeFiles(rel, exec);
    return -1;
  }

  if (runPostlinker(exec, rel, output)) {
    LOG_ERROR("Postlinker failed");
    closeFiles(exec, rel, output);
    return -1;
  } else {
    closeFiles(exec, rel, output);
    return 0;
  }
}

