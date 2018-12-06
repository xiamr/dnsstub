//
// Created by xiamr on 11/27/18.
//
#include "config.h"
#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include <fmt/printf.h>
#include "Global.h"

bool c_timeout = false;

// Example of __DATE__ string: "Jul 27 2012"
// Example of __TIME__ string: "21:06:19"

#define COMPUTE_BUILD_YEAR \
    ( \
        (__DATE__[ 7] - '0') * 1000 + \
        (__DATE__[ 8] - '0') *  100 + \
        (__DATE__[ 9] - '0') *   10 + \
        (__DATE__[10] - '0') \
    )


#define COMPUTE_BUILD_DAY \
    ( \
        ((__DATE__[4] >= '0') ? (__DATE__[4] - '0') * 10 : 0) + \
        (__DATE__[5] - '0') \
    )


#define BUILD_MONTH_IS_JAN (__DATE__[0] == 'J' && __DATE__[1] == 'a' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_FEB (__DATE__[0] == 'F')
#define BUILD_MONTH_IS_MAR (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'r')
#define BUILD_MONTH_IS_APR (__DATE__[0] == 'A' && __DATE__[1] == 'p')
#define BUILD_MONTH_IS_MAY (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'y')
#define BUILD_MONTH_IS_JUN (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_JUL (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'l')
#define BUILD_MONTH_IS_AUG (__DATE__[0] == 'A' && __DATE__[1] == 'u')
#define BUILD_MONTH_IS_SEP (__DATE__[0] == 'S')
#define BUILD_MONTH_IS_OCT (__DATE__[0] == 'O')
#define BUILD_MONTH_IS_NOV (__DATE__[0] == 'N')
#define BUILD_MONTH_IS_DEC (__DATE__[0] == 'D')


#define COMPUTE_BUILD_MONTH \
    ( \
        (BUILD_MONTH_IS_JAN) ?  1 : \
        (BUILD_MONTH_IS_FEB) ?  2 : \
        (BUILD_MONTH_IS_MAR) ?  3 : \
        (BUILD_MONTH_IS_APR) ?  4 : \
        (BUILD_MONTH_IS_MAY) ?  5 : \
        (BUILD_MONTH_IS_JUN) ?  6 : \
        (BUILD_MONTH_IS_JUL) ?  7 : \
        (BUILD_MONTH_IS_AUG) ?  8 : \
        (BUILD_MONTH_IS_SEP) ?  9 : \
        (BUILD_MONTH_IS_OCT) ? 10 : \
        (BUILD_MONTH_IS_NOV) ? 11 : \
        (BUILD_MONTH_IS_DEC) ? 12 : \
        /* error default */  99 \
    )

#define COMPUTE_BUILD_HOUR ((__TIME__[0] - '0') * 10 + __TIME__[1] - '0')
#define COMPUTE_BUILD_MIN  ((__TIME__[3] - '0') * 10 + __TIME__[4] - '0')
#define COMPUTE_BUILD_SEC  ((__TIME__[6] - '0') * 10 + __TIME__[7] - '0')


#define BUILD_DATE_IS_BAD (__DATE__[0] == '?')

#define BUILD_YEAR  ((BUILD_DATE_IS_BAD) ? 99 : COMPUTE_BUILD_YEAR)
#define BUILD_MONTH ((BUILD_DATE_IS_BAD) ? 99 : COMPUTE_BUILD_MONTH)
#define BUILD_DAY   ((BUILD_DATE_IS_BAD) ? 99 : COMPUTE_BUILD_DAY)

#define BUILD_TIME_IS_BAD (__TIME__[0] == '?')

#define BUILD_HOUR  ((BUILD_TIME_IS_BAD) ? 99 :  COMPUTE_BUILD_HOUR)
#define BUILD_MIN   ((BUILD_TIME_IS_BAD) ? 99 :  COMPUTE_BUILD_MIN)
#define BUILD_SEC   ((BUILD_TIME_IS_BAD) ? 99 :  COMPUTE_BUILD_SEC)


bool Global::debugMode = false;

std::string Global::parseArguments(int argc, char *argv[]) {

  std::string config_filename;

  boost::program_options::options_description desc("Dns cache server for bypassing great firewall");
  desc.add_options()
      ("help,h", "show this help message")
      ("config,c", boost::program_options::value<std::string>(&config_filename)->required(),
       "config file (json or xml format)")
      ("debug,d",boost::program_options::value<bool>(&debugMode)->zero_tokens(),"debug severity mode");

  boost::program_options::positional_options_description p;
  p.add("config", 1);
  boost::program_options::variables_map variablesMap;
  boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                    .options(desc).positional(p).run(), variablesMap);

  if (variablesMap.count("help")) {
    std::cout << desc;
    exit(EXIT_SUCCESS);
  }
  if (!variablesMap.count("config")) {
    std::cerr << "--config option is required" << std::endl;
    std::cerr << desc;
    exit(EXIT_FAILURE);
  }

  boost::program_options::notify(variablesMap);
  return config_filename;
}

void Global::printVersionInfos() {
  std::cout << "----------------------------------------------------------------------" << std::endl;
  std::cout << "CMake Configure Time : " << CMAKE_CONFIGURE_TIME << std::endl;
  std::cout << "  Binaray Build Time : " << fmt::sprintf("%04d-%02d-%02d %02d:%02d:%2d\n",
                                                         BUILD_YEAR, BUILD_MONTH, BUILD_DAY, BUILD_HOUR, BUILD_MIN,
                                                         BUILD_SEC);
  std::cout << "             Version : " << DNSSTUB_VERSION << std::endl;
  std::cout << "              Author : " << DNSSTUB_AUTHOR << std::endl;
  std::cout << "----------------------------------------------------------------------" << std::endl << std::endl;
}
