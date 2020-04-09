#include "elf.h"

#include <algorithm>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>


using std::vector;
using std::string;
using std::unordered_map;
using std::pair;

using headerT = Elf64_Ehdr;
using segmentT = Elf64_Phdr;
using sectionT = Elf64_Shdr;
using indexSecVecT = vector<vector<pair<int, sectionT>>>;

using relaT = Elf64_Rela;
using relT = Elf64_Rel;
using symT = Elf64_Sym;

namespace constants {

const int kR = 0x4;
const int kRX = 0x5;
const int kRW = 0x6;
const int kRWX = 0x7;
const int kPageSize = 0x1000;

}  // namespace constants


typedef struct Context {
  int file_end;
  uint32_t base_address;
  int orig_start;
  int created_offset;
} Context;


void LOG_ERROR(const std::string& msg) {
  std::cout << "ERROR: " << msg << ". Exiting\n";
  exit(1);
}


void HANDLE_ERROR(int&& res, const string&& s) {
  if (res < 0) {
    LOG_ERROR(s);
  }
}


bool isPCReference(unsigned int type) {
  return type == R_X86_64_PC32 || type == R_X86_64_PLT32;
}


bool isAbsReference64(unsigned int type) {
  return type == R_X86_64_64;
}


bool isAbsReference32(unsigned int type) {
  return type == R_X86_64_32 || type == R_X86_64_32S;
}


bool correctSymbolType(unsigned int type) {
  return type == STT_NOTYPE || type == STT_FUNC || type == STT_OBJECT || type == STT_SECTION;
}


template <class... Args>
void closeFiles(Args... args) {
  auto files = {args...};
  std::for_each(files.begin(), files.end(), [](FILE* f){
      if (f) {
        if (fclose(f)) {
          LOG_ERROR("Filed to close file");
        };
      }
  });
}


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
void readHeaders(FILE* fd, const headerT& elfh, vector<T>& v, int count, int offset) {

  HANDLE_ERROR(fseek(fd, offset, 0),
               "readHeaders: fseek");
  for(int i = 0; i < count; ++i) {
    T tmp;
    HANDLE_ERROR(fread((char *)&tmp, sizeof tmp, 1, fd),
                 "readHeaders: fread");
    v.emplace_back(tmp);
  }
}


template <typename T>
void readSectionEntries(FILE* fd, const sectionT& s, vector<T>& sections) {
  HANDLE_ERROR(fseek(fd, s.sh_offset, SEEK_SET),
               "readSectionEntries: fseek");
  int count = s.sh_size / (sizeof(T));
  while (count) {
    T sec;
    HANDLE_ERROR(fread((char*)&sec, sizeof sec, 1, fd),
                 "readSectionEntries: fread");
    sections.emplace_back(sec);
    --count;
  }
}


void readRelocationEntities(FILE* fd, const sectionT& s,
                            vector<pair<string, relaT>>& sections,
                            const vector<char>& section_names) {
  HANDLE_ERROR(fseek(fd, s.sh_offset, SEEK_SET),
               "readRelocationEntities: fseek");
  int count = s.sh_size / (sizeof(relaT));
  string section_name = getName(s.sh_name, section_names).substr(5);
  while (count) {
    relaT sec;
    HANDLE_ERROR(fread((char*)&sec, sizeof sec, 1, fd),
                 "readRelocationEntities: fread");
    sections.emplace_back(std::make_pair(section_name, sec));
    --count;
  }
}


void readStrings(FILE* fd, const sectionT& s, vector<char>& strings) {
  vector<char> raw_strings(s.sh_size);
  HANDLE_ERROR(fseek(fd, s.sh_offset, SEEK_SET),
               "readStrings: fseek");
  HANDLE_ERROR(fread((char*)raw_strings.data(), s.sh_size, 1, fd),
               "readStrings: fread");
  strings = raw_strings;
}
