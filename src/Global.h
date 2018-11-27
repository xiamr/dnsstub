//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_GLOBAL_H
#define DNSSTUB_GLOBAL_H

#include <string>

extern bool c_timeout;

class Global {
  Global() = default;

public:
  static std::string parseArguments(int argc, char *argv[]);
  static void printVersionInfos();

};


#endif //DNSSTUB_GLOBAL_H
