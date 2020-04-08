#include "elf.h"
#include "utils.h"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <sys/stat.h>


using headerT = Elf64_Ehdr;
using segmentT = Elf64_Phdr;
using sectionT = Elf64_Shdr;

using relaT = Elf64_Rela;
using relT = Elf64_Rel;
using symT = Elf64_Sym;

using std::vector;
using std::string;
using std::unordered_map;
using std::pair;


string getName(unsigned index, vector<char> strings) {
  std::string tmp = "";
  if (index < strings.size() && index >= 0) {
    char c = strings[index];
    while (c != '\0') {
      tmp += c;
      ++index;
      c = strings[index];
    }
    return tmp;
  }
  return "";
}

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
  fseek(fd, s.sh_offset, SEEK_SET);
  int count = s.sh_size / (sizeof(T));
  while (count) {
    T sec;
    fread((char*)&sec, sizeof sec, 1, fd);
    sections.emplace_back(sec);
    --count;
  }
}

void readRelocationEntities(FILE* fd, sectionT& s,
                            vector<pair<string, relaT>>& sections,
                            vector<char>& section_names) {
  fseek(fd, s.sh_offset, SEEK_SET);
  int count = s.sh_size / (sizeof(relaT));
  string section_name = getName(s.sh_name, section_names).substr(5);
  while (count) {
    relaT sec;
    fread((char*)&sec, sizeof sec, 1, fd);
    sections.emplace_back(std::make_pair(section_name, sec));
    --count;
  }
}

void readStrings(FILE* fd, sectionT& s, vector<char>& strings) {
  vector<char> raw_strings(s.sh_size);

  fseek(fd, s.sh_offset, SEEK_SET);
  fread((char*)raw_strings.data(), s.sh_size, 1, fd);
  strings = raw_strings;
}

int extractSectionInfo(vector<vector<pair<int, sectionT>>>& sections,
                       const vector<char>& section_names,
                       const string& section_name, bool offset) {
  for (auto& v : sections) {
    for (auto& new_s : v) {
      if (getName(new_s.second.sh_name, section_names) == section_name) {
        if (offset) {
          return new_s.second.sh_offset;
        } else {
          return new_s.second.sh_addr;
        }
      }
    }
  }
  return -1;
}


uint64_t getSectionOffset(const vector<vector<pair<int, sectionT>>>& sections, int index) {

  for (auto& v : sections) {
    for (auto& p : v) {
      if (p.first == index) {
        return p.second.sh_offset;
      }
    }
  }
  std::cout << "Failed\n";
  return 0;
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
  ctx.created_offset = size;
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
  header.e_shoff += ctx.created_offset;
}

void addNewSegment(Context& ctx, headerT& header,
                   vector<segmentT>& segments,
                   vector<pair<int, sectionT>>& sections,
                   vector<sectionT>& rel_sections,
                   int segment_flags) {
  if (sections.size()) {
    std::cout << "Adding new segment\n";
    segmentT p;
    int size = 0;
    int new_off = ctx.file_end;

    if (new_off % constants::kPageSize != 0) {
      new_off += constants::kPageSize - (new_off % constants::kPageSize);
    }
    std::for_each(sections.begin(), sections.end(), [&](pair<int, sectionT> s) {
        for(auto& rel_s : rel_sections) {
          if (rel_s.sh_name == s.second.sh_name) {
            rel_s.sh_offset = new_off + size;
            s.second.sh_offset = rel_s.sh_offset;
            std::cout << "New offset = " << rel_s.sh_offset << "\n";
            break;
          }
        }
        if (size % s.second.sh_addralign != 0) {
          size += s.second.sh_addralign - (size % s.second.sh_addralign);
        };
        size += s.second.sh_size;
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
                      headerT& output_header, headerT& rel_header,
                      headerT& exec_header,
                      vector<sectionT>& exec_sections,
                      vector<sectionT>& rel_sections,
                      vector<sectionT>& output_sections,
                      vector<vector<pair<int, sectionT>>>& output_new_sections) {
  vector<relT> rels;
  vector<pair<string, relaT>> relas;
  vector<symT> rel_syms, exec_syms;
  vector<char> rel_strings, rel_section_names, exec_strings;
  int section_id = 0;

  readStrings(rel, rel_sections[rel_header.e_shstrndx], rel_section_names);

  for (auto& s : rel_sections) {
    if (s.sh_type == SHT_STRTAB && section_id != rel_header.e_shstrndx) {
      readStrings(rel, s, rel_strings);
    } else if (s.sh_type == SHT_RELA) {
      readRelocationEntities(rel, s, relas, rel_section_names);
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

  int i = 0;
  for (auto& r : relas) {
    int32_t symbol_address;
    auto& symbol = rel_syms[ELF64_R_SYM(r.second.r_info)];
    auto sym_name = getName(symbol.st_name, rel_strings);
    int section_offset;
    if (correctSymbolType(ELF64_ST_TYPE(symbol.st_info))) {
      if (symbol.st_shndx == SHN_UNDEF) {
        if (sym_name == "orig_start") {
          std::cout << "orig_start\n";
          symbol_address = ctx.orig_start;
          section_offset = extractSectionInfo(output_new_sections,
                                              rel_section_names,
                                              ".text", true);
        } else {
          bool found = false;
          for (auto& exec_s : exec_syms) {
            auto exec_name = getName(exec_s.st_name, exec_strings);
            if (exec_name == sym_name) {
              found = true;
              symbol_address = exec_s.st_value;
              std::cout << "name: " << exec_name << "\n";
            }
          }
          if (!found) continue;
        }
      } else {
        section_offset = getSectionOffset(output_new_sections, symbol.st_shndx);
        symbol_address = section_offset + symbol.st_value + ctx.base_address;
      }
      /* auto section_offset = rel_sections[symbol.st_shndx].sh_offset; */
      int32_t rel_section_offset = extractSectionInfo(output_new_sections,
                                                      rel_section_names, r.first, true);
      int32_t instr_address = rel_section_offset + r.second.r_offset + ctx.base_address;
      auto addend = r.second.r_addend;
      fseek(output, instr_address - ctx.base_address, 0);
      uint64_t r_type = ELF64_R_TYPE(r.second.r_info);
      if (isPCReference(r_type)) {
        int32_t address = symbol_address + addend - instr_address;
        std::cout << "1: Address: " << address << "\n";
        fwrite(&address, 1, sizeof(int32_t), output);
      } else if (isAbsReference32(r_type)) {
        int32_t address = symbol_address + addend;
        std::cout << "2: Address: " << address << "\n";
        fwrite(&address, 1, sizeof(int32_t), output);
      } else if (isAbsReference64(r_type)) {
        int64_t address = symbol_address + addend;
        std::cout << "2: Address: " << address << "\n";
        fwrite(&address, 1, sizeof(int64_t), output);
      }
    }
    ++i;
  }

  // Save header
  for (auto& s : rel_syms) {
    if(getName(s.st_name, rel_strings) == "_start") {
    output_header.e_entry = s.st_value;
    auto s_off =  extractSectionInfo(output_new_sections, rel_section_names, ".text", false);
    output_header.e_entry += s_off;
    std::cout << "section_offset : " << s_off << "\n";
    std::cout << "start : " << output_header.e_entry << "\n";
    break;
    }
  }
  fseek(output, 0, 0);
  fwrite(&output_header, 1, sizeof(output_header), output);
}

void saveOutput(Context& ctx, headerT& output_header, vector<segmentT>& output_segments,
                vector<sectionT>& output_sections, vector<sectionT>& exec_sections,
                vector<vector<pair<int, sectionT>>>& rel_sections,
                FILE* output, FILE* exec, FILE* rel) {
  // Save segment headers
  fseek(output, output_header.e_phoff, 0);
  for (auto& p : output_segments) {
      fwrite(&p, 1, sizeof(segmentT), output);
  };

  // Save Sections
  for (int i = 0; i < output_sections.size(); ++i) {
    if (i != 0) {
      auto& o_s = output_sections[i];
      auto& e_s = exec_sections[i];
      vector<char> tmp(o_s.sh_size);
      if (i != 0) {
        o_s.sh_offset += ctx.created_offset;
      }
      fseek(exec, e_s.sh_offset, 0);
      fread((char*)tmp.data(), 1, e_s.sh_size, exec);
      fseek(output, o_s.sh_offset, 0);
      int pos = ftell(output);
      if (o_s.sh_addralign != 0 && pos % o_s.sh_addralign != 0) {
        fseek(output, o_s.sh_addralign - (pos % o_s.sh_addralign), SEEK_CUR);
      }
      fwrite(tmp.data(), o_s.sh_size, sizeof(char), output);
    }
  }

  /* output_header.e_shoff = ftell(output); */

  // Saving section headers
  fseek(output, output_header.e_shoff, 0);
  for (auto& s : output_sections) {
    fwrite(&s, 1, sizeof(sectionT), output);
  };

  fseek(output, ctx.file_end, 0);
  // Saving rel sections
  for (auto& v : rel_sections) {
    if (v.size()) {
      auto pos = ftell(output);
      if (pos % constants::kPageSize != 0) {
        pos += constants::kPageSize - (pos % constants::kPageSize);
        fseek(output, pos, 0);
      }
      for (auto& p : v) {
        vector<char> tmp(p.second.sh_size);
        fseek(rel, p.second.sh_offset, 0);
        fread((char*)tmp.data(), p.second.sh_size, 1, rel);

        pos = ftell(output);
        std::cout << "Saving undder: " << pos << '\n';
        std::cout << "Section size: " << p.second.sh_size << '\n';
        if (p.second.sh_addralign != 0 && pos % p.second.sh_addralign != 0) {
          fseek(output, p.second.sh_addralign - (pos % p.second.sh_addralign), SEEK_CUR);
        }
        p.second.sh_addr = ctx.base_address + ftell(output);
        p.second.sh_offset = ftell(output);
        std::cout << "base: " << ctx.base_address << "\n";
        std::cout << "new offset: " << p.second.sh_offset << "\n";
        std::cout << "new_add : " << p.second.sh_offset + ctx.base_address << "\n";
        fwrite(tmp.data(), p.second.sh_size, sizeof(char), output);
      }
    }
  }
  return;
}


int runPostlinker(FILE *exec, FILE *rel, FILE *output) {

  headerT exec_header, rel_header, out_header;
  vector<segmentT> exec_segments, output_segments;
  vector<sectionT> exec_sections, rel_sections, output_sections;
  Context ctx;

  // Executable
  fread((char *)&exec_header, sizeof exec_header, 1, exec);
  ctx.orig_start = exec_header.e_entry;

  readHeaders(exec, exec_header, exec_segments,
              exec_header.e_phnum, exec_header.e_phoff);
  readHeaders(exec, exec_header, exec_sections,
              exec_header.e_shnum, exec_header.e_shoff);
  fseek(exec, 0, SEEK_END);
  ctx.file_end = ftell(exec);
  findBaseAddress(ctx, exec_segments);

  out_header = exec_header;
  output_segments = exec_segments;
  output_sections = exec_sections;

  // Relocatable
  fread((char *)&rel_header, sizeof rel_header, 1, rel);
  readHeaders(rel, rel_header, rel_sections,
              rel_header.e_shnum, rel_header.e_shoff);


  vector<pair<int, sectionT>> RSections, RWSections, RXSections, RWXSections;

  int section_id = 0;
  for (auto& s : rel_sections) {
    if (s.sh_flags & SHF_ALLOC) {
      if ((s.sh_flags & SHF_EXECINSTR)
          && (s.sh_flags & SHF_WRITE) && s.sh_size != 0) {
        RWXSections.emplace_back(std::make_pair(section_id, s));
      } else if (s.sh_flags & SHF_WRITE && s.sh_size != 0) {
        RWSections.emplace_back(std::make_pair(section_id, s));
      } else if (s.sh_flags & SHF_EXECINSTR && s.sh_size != 0) {
        RXSections.emplace_back(std::make_pair(section_id, s));
      } else if (s.sh_size != 0) {
        RSections.emplace_back(std::make_pair(section_id, s));
      }
    }
    ++section_id;
  }

  addNewSegment(ctx, out_header, output_segments, RSections, rel_sections, constants::kR);
  addNewSegment(ctx, out_header, output_segments, RWSections, rel_sections, constants::kRW);
  addNewSegment(ctx, out_header, output_segments, RXSections, rel_sections, constants::kRX);
  addNewSegment(ctx, out_header, output_segments, RWXSections, rel_sections, constants::kRWX);
  makeSpaceForHeaders(ctx, out_header, output_segments, exec_segments);

  vector<vector<pair<int, sectionT>>> chosen_sections = {RSections, RWSections, RXSections, RWXSections};

  saveOutput(ctx, out_header, output_segments, output_sections,
             exec_sections, chosen_sections, output, exec, rel);
  applyRelocations(ctx, rel, exec, output, out_header,
                   rel_header, exec_header, exec_sections,
                   rel_sections, output_sections, chosen_sections);

  return 0;
}


int main(int argc, char **argv) {

  if (argc != 4) {
    std::cout << "Usage: ./postlinker <ET_EXEC> <ET_REL> <output>\n";
    return -1;
  }

  const string file_error = "Failed to open file:";

  FILE *rel = fopen(argv[2], "rb");
  if (!rel) {
    LOG_ERROR(file_error + argv[2]);
    return -1;
  }

  FILE *exec = fopen(argv[1], "rb");
  if (!exec) {
    LOG_ERROR(file_error + argv[1]);
    closeFiles(rel);
    return -1;
  }

  FILE *output = fopen(argv[3], "w+");
  if (!output) {
    LOG_ERROR(file_error + argv[3]);
    closeFiles(rel, exec);
    return -1;
  }

  if (runPostlinker(exec, rel, output)) {
    LOG_ERROR("Postlinker failed");
    closeFiles(exec, rel, output);
    return -1;
  } else {
    closeFiles(exec, rel, output);
    chmod(argv[3], 0751);
    return 0;
  }
}

