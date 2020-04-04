#include "elf.h"
#include "utils.h"

#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <vector>

using headerT = Elf64_Ehdr;
using segmentT = Elf64_Phdr;
using sectionT = Elf64_Shdr;

using relaSectionT = Elf64_Rela;
using relSectionT = Elf64_Rel;
using symT = Elf64_Sym;

using std::vector;
using std::string;


void readSectionHeaders(FILE* fd, headerT& elfh, std::vector<sectionT>& sections) {
  fseek(fd, elfh.e_shoff,0);
  for(int i = 0; i < elfh.e_shnum; ++i) {
    sectionT tmp;
    fread((char *)&tmp, sizeof tmp, 1, fd);
    sections.emplace_back(tmp);
  }
}

void readSegmentHeaders(FILE* fd, headerT& elfh, std::vector<segmentT>& segments) {
  fseek(fd, elfh.e_phoff,0);
  for(int i = 0; i < elfh.e_phnum; ++i) {
    segmentT tmp;
    fread((char *)&tmp, sizeof tmp, 1, fd);
    segments.emplace_back(tmp);
  }
}


int runPostlinker(FILE *exec, FILE *rel, FILE *output) {

  headerT exec_header, rel_header, out_header;
  vector<segmentT> exec_segments, output_segments;
  vector<sectionT> exec_sections, output_sections;
  /* vector<relaSectionT> rela_sections; */
  /* vector<symT> symbols; */


  fread((char *)&exec_header, sizeof exec_header, 1, exec);

  readSegmentHeaders(exec, exec_header, exec_segments);
  readSectionHeaders(exec, exec_header, exec_sections);

  out_header = exec_header;
  output_segments = exec_segments;
  output_sections = exec_sections;

  out_header.e_phnum++;

  segmentT new_s;
  new_s.p_type = PT_NULL;
  new_s.p_type = 0x4;
  new_s.p_offset = 0;
  new_s.p_vaddr = 0;    /* Segment virtual address */
  new_s.p_paddr = 0;   /* Segment physical address */
  new_s.p_filesz = 0;   /* Segment size in file */
  new_s.p_memsz = 0;    /* Segment size in memory */
  new_s.p_align = 0;


  fwrite(&out_header, 1, sizeof(out_header), output);
  fseek(output, out_header.e_phnum * out_header.e_phentsize, 0);
  fwrite(&new_s, 1, sizeof(new_s), output);
  fseek(output, out_header.e_phoff, 0);
  fwrite(exec_segments.data(), exec_segments.size(), sizeof(segmentT), output);
  fseek(output, out_header.e_shoff, 0);
  fwrite(exec_sections.data(), exec_sections.size(), sizeof(sectionT), output);



  /* vector<vector<std::pair<int, string>>> strings; */

  /* for (auto& s : sections) { */
  /*   if (s.sh_type == SHT_STRTAB) { */
  /*     std::cout << s.sh_link << "\n"; */
  /*     vector<char> raw_strings(s.sh_size); */
  /*     string tmp; */
  /*     vector<pair<int, string>> section_strings; */

  /*     fseek(fd, s.sh_offset,0); */
  /*     fread((char*)raw_strings.data(), s.sh_size, 1, fd); */
  /*     int i = 0; */
  /*     for (auto c : raw_strings) { */ 
  /*       if (c != '\0') { */
  /*         tmp += c; */
  /*       } else if (tmp.size()) { */
  /*         section_strings.emplace_back({i,tmp}); */
  /*         tmp = ""; */
  /*       } */
  /*       ++i; */
  /*     } */
  /*     if (section_strings.size()) { */
  /*       strings.emplace_back(section_strings); */
  /*     } */
  /*   } */
  /*   if (s.sh_type == SHT_RELA) { */
  /*     fseek(fd, s.sh_offset, 0); */
  /*     int count = s.sh_size / (sizeof(relaSectionT)); */
  /*     while (count) { */
  /*       relaSectionT sec; */
  /*       fread((char*)&sec, sizeof sec, 1, fd); */
  /*       rela_sections.emplace_back(sec); */
  /*       --count; */
  /*     } */
  /*   } */
  /*   if (s.sh_type == SHT_SYMTAB) { */
  /*     fseek(fd, s.sh_offset, 0); */
  /*     int count = s.sh_size / (sizeof(symT)); */
  /*     while (count) { */
  /*       symT sec; */
  /*       fread((char*)&sec, sizeof sec, 1, fd); */
  /*       symbols.emplace_back(sec); */
  /*       --count; */
  /*     } */
  /*   } */
  /* } */
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
  }





  return 0;
}



  
