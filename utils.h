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

