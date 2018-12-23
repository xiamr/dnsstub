//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_GLOBAL_H
#define DNSSTUB_GLOBAL_H

#include <string>



class Config;

class Global {
  Global() = default;

public:
  static std::string parseArguments(int argc, char *argv[]);
  static void printVersionInfos();

  static bool debugMode;

  static Config *config;

};


#endif //DNSSTUB_GLOBAL_H
