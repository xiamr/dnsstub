//
// Created by xiamr on 11/27/18.
//

#include <vector>

#include "DnsQueryStatistics.h"
#include "Dns.h"

void DnsQueryStatistics::printStatisticsInfos() {
  std::ostream *os = nullptr;
  if (statisticsFileName.empty()) {
    os = &(std::cout);
  } else {
    auto ofs = new std::ofstream();
    os = ofs;
    ofs->open(statisticsFileName);
    if (ofs->fail()) {
      std::cerr << "error opening statisticsInfo file <" << statisticsFileName << "> !" << std::endl;
      delete ofs;
      return;
    }
  }
  *os << "---------------------- statistics ------------------------" << std::endl;

  int max_name_len = 0;
  std::vector<std::unordered_map<Dns::Question, long, KeyHasher>::iterator> result_list;
  for (auto iterator = _statistics.begin(); iterator != _statistics.end(); ++iterator) {
    max_name_len = std::max(max_name_len, static_cast<int>(iterator->first.name.length()));
    result_list.push_back(iterator);
  }

  std::__cxx11::string format_str1 = fmt::sprintf("%%%ds%%10s%%10s%%12s\n", max_name_len + 5);
  std::__cxx11::string format_str2 = fmt::sprintf("%%%ds%%10s%%10s%%12d\n", max_name_len + 5);

  *os << fmt::sprintf(format_str1, "Name", "Class", "Type", "Count");

  // sort count by descending order
  std::sort(result_list.begin(), result_list.end(), [](auto &i1, auto &i2) { return (i1->second > i2->second); });
  long total_count = 0;
  for (auto &item : result_list) {
    auto &q = item->first;
    *os << fmt::sprintf(format_str2, q.name, Dns::QClass2Name[q.Class], Dns::QType2Name[q.Type], item->second);
    total_count += item->second;
  }
  *os << "----------------------------------------------------------" << std::endl;
  *os << fmt::sprintf(fmt::sprintf("Total%%%dd\n", max_name_len + 10 + 10 + 12), total_count);
  *os << "----------------------------------------------------------" << std::endl;
  if (typeid(*os) == typeid(std::ofstream)) {
    delete os;
  }
}

void DnsQueryStatistics::countNewQuery(const Dns &dns) {
  auto iterator = _statistics.find(dns.questions.front());
  if (iterator != _statistics.end()) {
    (*iterator).second++;
  } else {
    _statistics[dns.questions.front()] = 1;
  }
}
