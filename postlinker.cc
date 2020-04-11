#include <climits>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"

#include "utils.h"

/* Extract offset or address of a rel section based on its name */
uint64_t extractSectionInfo(const indexSecVecT& sections,
                            const vector<char>& section_names,
                            unordered_map<int, uint64_t>& offset_map,
                            const string& section_name) {
  for (auto& v : sections) {
    for (auto& new_s : v) {
      if (getName(new_s.second.sh_name, section_names) == section_name) {
        return offset_map[new_s.first];
      }
    }
  }
  LOG_ERROR("Could not find the section: " + section_name);
  return 0;
}

/* Extract offset of a rel section based on its index */
uint64_t getSectionOffset(const indexSecVecT& sections, int index) {

  for (auto& v : sections) {
    for (auto& p : v) {
      if (p.first == index) {
        return p.second.sh_offset;
      }
    }
  }
  LOG_ERROR("Could not find section with id: " + index);
  return 0;
}


/* Calculate base address */
void findBaseAddress(Context& ctx, const vector<segmentT>& segments) {
  uint32_t min = UINT_MAX;
  for (auto& p : segments) {
    if (p.p_type == PT_LOAD && p.p_vaddr < min) {
      min = p.p_vaddr;
    }
  }
  ctx.base_address = min;
}


/* Move bottom segment down in order to make space
 * for new segment headers */
void makeSpaceForHeaders(Context& ctx, headerT& header,
                         vector<segmentT>& out_segments,
                         const vector<segmentT>& exec_segments,
                         unordered_map<int, uint64_t>& offset_map) {
  int offset = 0;
  auto exec_size = exec_segments.size();
  uint32_t segment_off;

  offset = (out_segments.size() - exec_size) * sizeof(segmentT);
  if (offset % constants::kPageSize != 0) {
    offset += constants::kPageSize - (offset % constants::kPageSize);
  }

  if (exec_segments[0].p_type == PT_PHDR) {
    segment_off = exec_segments[0].p_filesz;
  } else {
    segment_off = header.e_phoff + sizeof(segmentT) * exec_segments.size();
  }
  for (auto& p : out_segments) {
    if (p.p_offset < segment_off) {
      p.p_paddr = std::max(int64_t(p.p_paddr - constants::kPageSize), int64_t(0));
      p.p_vaddr = std::max(int64_t(p.p_vaddr - constants::kPageSize), int64_t(0));
      if (p.p_type == PT_LOAD) {
        p.p_memsz += constants::kPageSize;
        p.p_filesz += constants::kPageSize;
      }
    }
  }
  findBaseAddress(ctx, out_segments);

  for (auto& p : out_segments) {
    if (p.p_type != PT_PHDR && p.p_offset != 0) {
      p.p_offset += constants::kPageSize;
    }
  }
  header.e_shoff += constants::kPageSize;
  for (auto& v : offset_map) {
    v.second += constants::kPageSize;
  }
}

/* Add new segment containg passed sections
 * with <segment_flags> permissions */
void addNewSegment(Context& ctx, headerT& header,
                   vector<segmentT>& segments,
                   const vector<pair<int, sectionT>>& sections,
                   vector<sectionT>& rel_sections,
                   unordered_map<int, uint64_t>& offset_map,
                   int segment_flags) {
  if (sections.size()) {
    std::cout << "Adding new segment\n";
    segmentT p;
    int size = 0;
    int new_off = ctx.file_end;
    if (new_off % constants::kPageSize != 0) {
      new_off += constants::kPageSize - (new_off % constants::kPageSize);
    }
    ctx.file_end = new_off;
    for (auto& s : sections) {
        if (size % s.second.sh_addralign != 0) {
          size += s.second.sh_addralign - (size % s.second.sh_addralign);
        };
        offset_map[s.first] = new_off + size;
        size += s.second.sh_size;
    }
    if (size != 0) {
      p.p_type = PT_LOAD;
      p.p_flags = segment_flags;
      p.p_offset = new_off;
      p.p_vaddr = new_off + ctx.base_address;
      p.p_paddr = new_off + ctx.base_address;
      p.p_filesz = size;
      p.p_memsz = size;
      p.p_align = constants::kPageSize;
      segments.emplace_back(p);

      header.e_phnum++;
      ctx.file_end += size;
    }
  }
}

void handleRelocation(Context& ctx, FILE* output, pair<string, relaT>& r,
                      const vector<symT>& rel_syms, const vector<symT>& exec_syms,
                      const vector<char>& rel_strings, const vector<char>& exec_strings,
                      const vector<char>& rel_section_names,
                      const indexSecVecT& chosen_sections,
                      unordered_map<int, uint64_t>& offset_map) {
  int32_t symbol_address;
  auto& symbol = rel_syms[ELF64_R_SYM(r.second.r_info)];
  auto sym_name = getName(symbol.st_name, rel_strings);
  int section_offset;
  if (correctSymbolType(ELF64_ST_TYPE(symbol.st_info))) {
    if (symbol.st_shndx != SHN_UNDEF) {
      section_offset = getSectionOffset(chosen_sections, symbol.st_shndx);
      symbol_address = section_offset + symbol.st_value + ctx.base_address;
    } else {
      if (sym_name == "orig_start") {
        symbol_address = ctx.orig_start;
        section_offset = extractSectionInfo(chosen_sections, rel_section_names,
                                            offset_map, ".text");
      } else {
        bool found = false;
        for (auto& exec_s : exec_syms) {
          auto exec_name = getName(exec_s.st_name, exec_strings);
          if (exec_name == sym_name) {
            found = true;
            symbol_address = exec_s.st_value;
          }
        }
        if (!found) LOG_ERROR("Could not find symbol " + sym_name);
      }
    }

    int32_t rel_section_offset = extractSectionInfo(chosen_sections, rel_section_names,
                                                    offset_map, r.first);
    int32_t instr_address = rel_section_offset + r.second.r_offset + ctx.base_address;
    auto addend = r.second.r_addend;
    uint64_t r_type = ELF64_R_TYPE(r.second.r_info);

    HANDLE_ERROR(fseek(output, instr_address - ctx.base_address, SEEK_SET),
                 "handleRelocation: fseek 1");
    if (isAbsReference32(r_type)) {
      int32_t address = symbol_address + addend;
      HANDLE_ERROR(fwrite(&address, 1, sizeof(int32_t), output),
                   "handleRelocation: fwrite 1");
    } else if (isAbsReference64(r_type)) {
      int64_t address = symbol_address + addend;
      HANDLE_ERROR(fwrite(&address, 1, sizeof(int64_t), output),
                   "handleRelocation: fwrite 2");
    } else if (isPCReference(r_type)) {
      int32_t address = symbol_address + addend - instr_address;
      HANDLE_ERROR(fwrite(&address, 1, sizeof(int32_t), output),
                   "handleRelocation: fwrite 3");
    }
  }
}

/* Calculate and write relocations
 * Read needed strings and symbol tables
 * in the beggining */
void applyRelocations(Context& ctx, FILE* rel, FILE* exec, FILE* output,
                      headerT& output_header, const headerT& rel_header,
                      const headerT& exec_header,
                      const vector<sectionT>& exec_sections,
                      const vector<sectionT>& rel_sections,
                      const vector<sectionT>& output_sections,
                      const indexSecVecT& chosen_sections,
                      unordered_map<int, uint64_t>& offset_map) {
  vector<relT> rels;
  vector<pair<string, relaT>> relas;
  vector<symT> rel_syms, exec_syms;
  vector<char> rel_strings, rel_section_names, exec_strings;

  readStrings(rel, rel_sections[rel_header.e_shstrndx], rel_section_names);

  int section_id = 0;
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

  /* For each relocation, caculate address/offset
   * and save it in the file */
  for (auto& r : relas) {
    handleRelocation(ctx, output, r, rel_syms, exec_syms, rel_strings, exec_strings,
                     rel_section_names, chosen_sections, offset_map);
  }

  // Save header
  for (auto& s : rel_syms) {
    if(getName(s.st_name, rel_strings) == "_start") {
      auto section_offset = extractSectionInfo(chosen_sections, rel_section_names,
                                               offset_map, ".text");
      output_header.e_entry = s.st_value + section_offset + ctx.base_address;
      break;
    }
  }
  HANDLE_ERROR(fseek(output, 0, SEEK_SET), "applyRelocations: fseek 2");
  HANDLE_ERROR(fwrite(&output_header, 1, sizeof(output_header), output),
               "applyRelocations: fwrite 4");
}

/* Copy exec file to the output with a offset */
void saveSegmentContent(FILE* output, FILE* exec) {
  ssize_t r = 0, w = 0;
  vector<char> buff(constants::kPageSize);

  HANDLE_ERROR(fseek(exec, 0, SEEK_SET),
               "saveSegmentContent: fseek 1");
  HANDLE_ERROR(fseek(output, constants::kPageSize, SEEK_SET),
               "saveSegmentContent: fseek 2");
  while ((r = fread((char*)buff.data(), sizeof(char), constants::kPageSize, exec)) != 0) {
    if (r < 0) {
      LOG_ERROR("saveSegmentContent: fread");
    }
    if (r != 0) {
      w = fwrite((char*)buff.data(), sizeof(char), r, output);
      if (w < 0) {
        LOG_ERROR("saveSegmentContent: fwrite");
      }
    }
  }
}

/* Save chosen sections (sections with ALLOC)
 * to the output file */
void saveChosenSections(Context& ctx, FILE* output, FILE* rel,
                        indexSecVecT& chosen_sections,
                        unordered_map<int, uint64_t>& offset_map) {
  for (auto& v : chosen_sections) {
    if (v.size()) {
      for (auto& p : v) {
        vector<char> tmp(p.second.sh_size);
        HANDLE_ERROR(fseek(rel, p.second.sh_offset, SEEK_SET),
                     "saveChosenSections: fseek 1");
        HANDLE_ERROR(fread((char*)tmp.data(), p.second.sh_size, 1, rel),
                     "saveChosenSections: fread 1");
        HANDLE_ERROR(fseek(output, offset_map[p.first], SEEK_SET),
                     "saveChosenSections: fseek 2");
        p.second.sh_addr = ctx.base_address + ftell(output);
        p.second.sh_offset = ftell(output);
        HANDLE_ERROR(fwrite(tmp.data(), p.second.sh_size, sizeof(char), output),
                     "saveChosenSections: fwrite 1");
      }
    }
  }
}

/* Save headers and segments data to the output file */
void saveOutput(Context& ctx, headerT& output_header, const vector<segmentT>& output_segments,
                const vector<segmentT>& exec_segments, vector<sectionT>& rel_sections,
                vector<sectionT>& output_sections, const vector<sectionT>& exec_sections,
                indexSecVecT& chosen_sections, unordered_map<int, uint64_t>& offset_map,
                FILE* output, FILE* exec, FILE* rel) {

  // Copy exec data into output file
  saveSegmentContent(output, exec);

  // Save segment headers
  HANDLE_ERROR(fseek(output, output_header.e_phoff, SEEK_SET),
               "saveOutput: fseek 1");
  for (auto& p : output_segments) {
      HANDLE_ERROR(fwrite(&p, 1, sizeof(segmentT), output),
                   "saveOutput: fwrite 1");
  };

  // Saving section headers
  HANDLE_ERROR(fseek(output, output_header.e_shoff, SEEK_SET),
               "saveOutput: fseek 2");

  bool first = true;
  for (auto& s : output_sections) {
    if (!first) s.sh_offset += constants::kPageSize;
    else first = false;
    HANDLE_ERROR(fwrite(&s, 1, sizeof(sectionT), output),
                 "saveOutput: fwrite 2");
  };

  // Saving rel chosen sections content
  saveChosenSections(ctx, output, rel, chosen_sections, offset_map);

  HANDLE_ERROR(fseek(output, 0, SEEK_SET), "applyRelocations: fseek 3");
  HANDLE_ERROR(fwrite(&output_header, 1, sizeof(output_header), output),
               "applyRelocations: fwrite 3");
  return;
}

/* Read all headers, find sections to move
 * create segments, create space, apply relocations */
int runPostlinker(FILE *exec, FILE *rel, FILE *output) {

  Context ctx;
  headerT exec_header, rel_header, out_header;
  vector<segmentT> exec_segments, output_segments;
  vector<sectionT> exec_sections, rel_sections, output_sections;
  vector<pair<int, sectionT>> RSections, RWSections, RXSections, RWXSections;
  unordered_map<int, uint64_t> offset_map;

  // Executable content
  HANDLE_ERROR(fread((char *)&exec_header, sizeof exec_header, 1, exec),
               "runPostlinker: fread 1");
  ctx.orig_start = exec_header.e_entry;

  readHeaders(exec, exec_header, exec_segments,
              exec_header.e_phnum, exec_header.e_phoff);
  readHeaders(exec, exec_header, exec_sections,
              exec_header.e_shnum, exec_header.e_shoff);

  out_header = exec_header;
  output_segments = exec_segments;
  output_sections = exec_sections;

  findBaseAddress(ctx, exec_segments);
  HANDLE_ERROR(fseek(exec, 0, SEEK_END),
               "runPostlinker: fseek 1");
  ctx.file_end = ftell(exec);

  // Relocatable content
  HANDLE_ERROR(fread((char *)&rel_header, sizeof rel_header, 1, rel),
               "runPostlinker: fread 2");
  readHeaders(rel, rel_header, rel_sections,
              rel_header.e_shnum, rel_header.e_shoff);

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

  addNewSegment(ctx, out_header, output_segments, RSections,
                rel_sections, offset_map, constants::kR);
  addNewSegment(ctx, out_header, output_segments, RWSections,
                rel_sections, offset_map, constants::kRW);
  addNewSegment(ctx, out_header, output_segments, RXSections,
                rel_sections, offset_map, constants::kRX);
  addNewSegment(ctx, out_header, output_segments, RWXSections,
                rel_sections, offset_map, constants::kRWX);
  makeSpaceForHeaders(ctx, out_header, output_segments, exec_segments, offset_map);

  indexSecVecT chosen_sections = {RSections, RWSections, RXSections, RWXSections};
  saveOutput(ctx, out_header, output_segments, exec_segments, rel_sections, output_sections,
             exec_sections, chosen_sections, offset_map, output, exec, rel);
  applyRelocations(ctx, rel, exec, output, out_header, rel_header, exec_header,
                   exec_sections, rel_sections, output_sections, chosen_sections, offset_map);
  return 0;
}


int main(int argc, char **argv) {

  if (argc != 4) {
    std::cout << "Usage: ./poslinker <ET_EXEC> <ET_REL> <OUTPUT>\n";
    return 1;
  }

  string file_error = "Failed to open file:";
  FILE *rel = fopen(argv[2], "rb");
  if (!rel) {
    LOG_ERROR(file_error + argv[2]);
    return 1;
  }

  FILE *exec = fopen(argv[1], "rb");
  if (!exec) {
    LOG_ERROR(file_error + argv[1]);
    closeFiles(rel);
    return 1;
  }

  FILE *output = fopen(argv[3], "w+");
  if (!output) {
    LOG_ERROR(file_error + argv[3]);
    closeFiles(rel, exec);
    return 1;
  }

  if (runPostlinker(exec, rel, output)) {
    LOG_ERROR("Postlinker failed");
    closeFiles(exec, rel, output);
    return 1;
  } else {
    closeFiles(exec, rel, output);
    HANDLE_ERROR(chmod(argv[3], 0755), "main: chmod");
    return 0;
  }
}
