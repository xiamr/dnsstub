//
// Created by xiamr on 11/27/18.
//

#include <vector>

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <boost/stacktrace.hpp>

#include "DnsQueryStatistics.h"
#include "Dns.h"

void DnsQueryStatistics::printStatisticsInfos() {
  std::ostream *os = nullptr;
  if (statisticsFileName.empty()) {
    os = &(std::cout);
  } else {
    auto ofs = new std::ofstream();
    os = ofs;
    ofs->exceptions(ofs->exceptions() | std::ios::failbit);
    try {
      ofs->open(statisticsFileName);
    } catch (std::ios_base::failure &e) {
      BOOST_LOG_TRIVIAL(error) << "error opening statisticsInfo file <" << statisticsFileName << "> !" << e.what();
      BOOST_LOG_TRIVIAL(error) << boost::stacktrace::stacktrace();
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

  std::string format_str1 = (boost::format("%%%ds%%10s%%10s%%12s\n") % (max_name_len + 5)).str();
  std::string format_str2 = (boost::format("%%%ds%%10s%%10s%%12d\n") % (max_name_len + 5)).str();

  *os << boost::format(format_str1) % "Name" % "Class" % "Type" % "Count";

  // sort count by descending order
  std::sort(result_list.begin(), result_list.end(), [](auto &i1, auto &i2) { return (i1->second > i2->second); });
  long total_count = 0;
  for (auto &item : result_list) {
    auto &q = item->first;
    *os << boost::format(format_str2)
           % q.name
           % Dns::QClass2Name[q.Class]
           % Dns::QType2Name.left.find(q.Type)->second
           % item->second;
    total_count += item->second;
  }
  *os << "----------------------------------------------------------" << std::endl;
  *os << boost::format((boost::format("Total%%%dd\n") % (max_name_len + 10 + 10 + 12)).str()) % total_count;
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
