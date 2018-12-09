//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_DNSQUERYSTATISTICS_H
#define DNSSTUB_DNSQUERYSTATISTICS_H

#include "Dns.h"
#include <fmt/printf.h>
#include <boost/algorithm/string.hpp>
#include <regex>
#include <fstream>
#include <unordered_set>
#include <sstream>
#include <queue>
#include <unordered_map>
#include <map>
#include <list>
#include <tuple>
#include <iostream>
#include <sys/types.h>
#include <utility>

class Dns;

class DnsQueryStatistics {
  struct KeyHasher {
    std::size_t operator()(const Dns::Question &t) const {
      return ((std::hash<std::string>()(t.name)
               ^ (std::hash<uint16_t>()(t.Class) << 1)) >> 1)
             ^ (std::hash<uint16_t>()(t.Type) << 1);
    }
  };

  std::unordered_map<Dns::Question, long, KeyHasher> _statistics;
  std::string statisticsFileName;
public:
  explicit DnsQueryStatistics(std::string statisticsFileName) :
      statisticsFileName(move(statisticsFileName)) {
  }

  void countNewQuery(const Dns &dns);

  void printStatisticsInfos();
};

#endif //DNSSTUB_DNSQUERYSTATISTICS_H
