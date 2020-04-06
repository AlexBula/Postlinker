#include <algorithm>
#include <iostream>
#include <stdio.h>

void LOG_ERROR(const std::string& msg) {
  std::cout << "ERROR: " << msg << ". Exiting\n";
}


template <class... Args>
void closeFiles(Args... args) {
  auto files = {args...};
  std::for_each(files.begin(), files.end(), [](FILE* f){
      if (fclose(f))
        LOG_ERROR("Filed to close file");
      });
}

namespace constants {

const int kR = 0x4;
const int kRX = 0x5;
const int kRW = 0x6;
const int kRWX = 0x7;
const int kPageSize = 0x1000;

}  // namespace constants

enum RelocationType {
	/* R_X86_64_64 = 1, */
	/* R_X86_64_PC32 = 2, */
	/* R_X86_64_PLT32 = 4, */
	/* R_X86_64_32 = 10, */
	/* R_X86_64_32S = 11 */
  dupa = 1,
  chuj = 2
};


bool isPCReference(unsigned int type) {
  return type == R_X86_64_PC32 || type == R_X86_64_PLT32;
}

bool isAbsReference(unsigned int type) {
  return type == R_X86_64_64 || type == R_X86_64_32 || type == R_X86_64_32S;
}
