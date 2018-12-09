//
// Created by xiamr on 11/27/18.
//

#include <boost/program_options.hpp>
#include "json.hpp"
#include <chrono>       // std::chrono::system_clock
#include <random>       // std::default_random_engine
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
#include <vector>
#include <netinet/in.h>
#include <iostream>
#include <sys/types.h>
#include <utility>
#include <boost/assign.hpp>

#include "Global.h"
#include "DnsQueryStatistics.h"
#include "Dns.h"
#include "Cache.h"
#include "Config.h"


out_of_bound::out_of_bound(int line) : std::runtime_error(get_err_string(line)) {}

std::unordered_set<std::string> Dns::polluted_domains;

boost::bimap<boost::bimaps::set_of<Dns::QType>, boost::bimaps::set_of<std::string>> Dns::QType2Name = \
boost::assign::list_of<boost::bimap<boost::bimaps::set_of<Dns::QType>, boost::bimaps::set_of<std::string>>::relation >
    (A,     "A")   (NS,    "NS")   (CNAME, "CNAME") (SOA,   "SOA") (PTR,   "PTR")
    (MX,    "MX")  (TXT,   "TXT")  (AAAA,  "AAAA")  (SRV,   "SRV") (NAPTR, "NAPTR")
    (OPT,   "OPT") (IXPT,  "IXPT") (AXFR,  "AXFR")  (ANY,   "ANY");

std::unordered_map<enum Dns::QClass, std::string> Dns::QClass2Name = {
    {IN,      "IN"},
    {NOCLASS, "NOCLASS"},
    {ALL,     "ALL"}
};

void Dns::from_wire(char *buf, int len) {
  char *ptr = buf;
  const char *upbound = buf + len;
  unsigned short qdcout;
  unsigned short ancout;
  unsigned short nscout;
  unsigned short arcout;
  id = ntohs_ptr(ptr, upbound);
  signs = ntohs_ptr(ptr, upbound);
  qdcout = ntohs_ptr(ptr, upbound);
  ancout = ntohs_ptr(ptr, upbound);
  nscout = ntohs_ptr(ptr, upbound);
  arcout = ntohs_ptr(ptr, upbound);
  for (unsigned short i = 0; i < qdcout; i++) {
    Question question;
    question.name = getName(ptr, buf, upbound);
    question.Type = (QType) ntohs_ptr(ptr, upbound);
    question.Class = (QClass) ntohs_ptr(ptr, upbound);
    if (question.Type != QType::PTR and !isDomainValid(question.name))
      throw BadDnsError("domain name error : " + question.name);
    questions.push_back(question);
  }
  for (unsigned short i = 0; i < ancout; i++) {
    Answer answer;
    answer.name = getName(ptr, buf, upbound);
    answer.Type = (QType) ntohs_ptr(ptr, upbound);
    answer.Class = (QClass) ntohs_ptr(ptr, upbound);
    if (answer.Type != QType::PTR and !isDomainValid(answer.name))
      throw BadDnsError("domain name error : " + answer.name);
    answer.TTL = ntohl_ptr(ptr, upbound);
    uint16_t RDLENGTH = ntohs_ptr(ptr, upbound);
    if (ptr + RDLENGTH - 1 > upbound) throw out_of_bound(__LINE__);
    char mybuf[1024];
    switch (answer.Type) {
      case A:
        answer.rdata = inet_ntop(AF_INET, ptr, mybuf, 1024);
        ptr += RDLENGTH;
        break;
      case AAAA:
        answer.rdata = inet_ntop(AF_INET6, ptr, mybuf, 1024);
        ptr += RDLENGTH;
        break;
      default:
        answer.rdata = getName(ptr, buf, upbound);
        if (!isDomainValid(answer.rdata))
          throw BadDnsError("domain name error : " + answer.rdata);
    }

    answers.push_back(answer);
  }
  if (!nscout) {
    for (unsigned short i = 0; i < arcout; i++) {
      Additional additional;
      if (ptr > upbound) throw out_of_bound(__LINE__);
      additional.name = static_cast<uint8_t>(*ptr);
      ptr++;
      additional.Type = ntohs_ptr(ptr, upbound);
      additional.playload_size = ntohs_ptr(ptr, upbound);
      if (ptr > upbound) throw out_of_bound(__LINE__);
      additional.high_bit_in_extend_rcode = static_cast<uint8_t>(*ptr);
      ptr++;
      if (ptr > upbound) throw out_of_bound(__LINE__);
      additional.edns0_verion = static_cast<uint8_t>(*ptr);
      ptr++;
      additional.Z = ntohs_ptr(ptr, upbound);
      additional.data_length = ntohs_ptr(ptr, upbound);
      additionals.push_back(additional);
    }
  }

  checkLocalnetType();
}

void Dns::checkLocalnetType() {
  if (0 == (signs & QR) and !questions.empty()) {
    std::string domain = questions.front().name;
    for (const auto &pattern : polluted_domains) {
      if (fnmatch(pattern.c_str(), domain.c_str(), FNM_CASEFOLD) == 0) {
        // Match
        use_localnet_dns_server = false;
        break;
      }
    }
  }
}

char *Dns::toName(std::string &origin_name, char *ptr, const char *buf, const char *upbound,
                  std::unordered_map<std::string, uint16_t> &str_map) {
  std::string name = origin_name;
  name.erase(name.end() - 1);
  if (name.length() == 0) {
    *ptr = '\0';
    ptr++;
    return ptr;
  }
  char *now_ptr = ptr;
  uint8_t sublen = 0;
  size_t pos = 0;
  try {
    uint16_t off = str_map.at(name.substr(pos));
    if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
    *(uint16_t *) ptr = htons(off);
    *ptr |= 0xc0;
    ptr += 2;
    return ptr;
  } catch (std::out_of_range &) {
    str_map[name.substr(pos)] = ptr - buf;
  }
  ptr++;
  for (char &c : name) {
    if (c == '.') {
      if (sublen) {
        if (now_ptr > upbound) throw out_of_bound(__LINE__);
        *now_ptr = sublen;
      }
      sublen = 0;
      pos++;
      try {
        uint16_t off = str_map.at(name.substr(pos));
        if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
        *(uint16_t *) ptr = htons(off);
        *ptr |= 0xc0;
        ptr += 2;
        return ptr;
      } catch (std::out_of_range &) {
        str_map[name.substr(pos)] = ptr - buf;
      }
      now_ptr = ptr;
      ptr++;
    } else {
      if (ptr > upbound) throw out_of_bound(__LINE__);
      *ptr = c;
      sublen++;
      ptr++;
      pos++;
    }

  }
  if (sublen) {
    *now_ptr = sublen;
  }
  *ptr = '\0';
  ptr++;
  return ptr;

}

std::string Dns::getName(char *&ptr, char *buf, const char *upbound) {
  std::string name;
  bool first = true;
  while (true) {
    if (ptr > upbound) throw out_of_bound(__LINE__);
    unsigned char count = *ptr;

    char *locate;
    if (count & 0xc0) {
      // compressed label
      if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
      locate = buf + 256 * (count & 0x3f) + *((uint8_t *) (ptr + 1));
      if (!first) name.append(1, '.');
      else first = false;
      name += getName(locate, buf, upbound);
      ptr += 2;
      break;
    } else {
      locate = ptr;
      ptr += count + 1;
    }
    if (count > 0) {
      if (locate + count > upbound) throw out_of_bound(__LINE__);
      if (!first) name.append(1, '.');
      else first = false;
      name.append(locate + 1, count);
    } else {
      name.append(1, '.');
      break;
    }
  }

  if (name.empty()) throw BadDnsError();
  return name;
}

void Dns::print() {
  std::cout << "id:" << id << std::endl;
  std::cout << "signs:" << signs << std::endl;
  std::cout << "qdcout:" << questions.size() << std::endl;
  std::cout << "ancout:" << answers.size() << std::endl;
  std::cout << "nscout:" << 0 << std::endl;
  std::cout << "arcout:" << 0 << std::endl;
  if (signs & QR) std::cout << "QR ";
  if (signs & AA) std::cout << "AA ";
  if (signs & TC) std::cout << "TC ";
  if (signs & RD) std::cout << "RD ";
  if (signs & RA) std::cout << "RA ";
  if (signs & AD) std::cout << "AD ";
  if (signs & CD) std::cout << "CD ";

  std::cout << "OpCode: " << get_opcode() << std::endl;
  std::cout << "RCode: " << get_rcode() << std::endl;

  std::cout << "Questions" << std::endl;
  for (auto &q : questions) {
    std::cout << q.name << "   " << QClass2Name[q.Class] << "  " << QType2Name.left.find(q.Type)->second << std::endl;
  }
  std::cout << "Answers" << std::endl;
  for (auto &ans : answers) {
    std::cout << ans.name << "  " << QClass2Name[ans.Class] << "   " << QType2Name.left.find(ans.Type)->second << "  " << ans.rdata
              << std::endl;
  }

}

ssize_t Dns::to_wire(char *buf, int n) {
  std::unordered_map<std::string, uint16_t> str_map;
  char *ptr = buf;
  const char *upbound = buf + n;
  htons_ptr(ptr, id, upbound);
  htons_ptr(ptr, signs, upbound);
  if (!(signs & QR) and GFW_mode and !use_localnet_dns_server) {
    htons_ptr(ptr, 2, upbound);
  } else {
    htons_ptr(ptr, questions.size(), upbound);
  }
  htons_ptr(ptr, answers.size(), upbound);
  htons_ptr(ptr, 0, upbound);
  htons_ptr(ptr, additionals.size(), upbound);
  if (!(signs & QR) and GFW_mode and !use_localnet_dns_server) {
    htons_ptr(ptr, 0xc012, upbound);
    htons_ptr(ptr, questions[0].Type, upbound);
    htons_ptr(ptr, questions[0].Class, upbound);
  }
  for (auto &q : questions) {
    ptr = toName(q.name, ptr, buf, upbound, str_map);
    htons_ptr(ptr, q.Type, upbound);
    htons_ptr(ptr, q.Class, upbound);
  }
  for (auto &ans : answers) {
    ptr = toName(ans.name, ptr, buf, upbound, str_map);
    htons_ptr(ptr, ans.Type, upbound);
    htons_ptr(ptr, ans.Class, upbound);
    htonl_ptr(ptr, ans.TTL, upbound);
    switch (ans.Type) {
      case A:
        htons_ptr(ptr, sizeof(in_addr), upbound);
        inet_pton(AF_INET, ans.rdata.c_str(), ptr);
        if (ptr + sizeof(struct in_addr) > upbound) throw out_of_bound(__LINE__);
        ptr += sizeof(struct in_addr);
        break;
      case AAAA:
        htons_ptr(ptr, sizeof(in6_addr), upbound);
        if (ptr + sizeof(struct in6_addr) > upbound) throw out_of_bound(__LINE__);
        inet_pton(AF_INET6, ans.rdata.c_str(), ptr);
        ptr += sizeof(struct in6_addr);
        break;
      default:
        char *len_ptr = ptr;
        ptr += 2;
        char *new_ptr = toName(ans.rdata, ptr, buf, upbound, str_map);
        if (len_ptr + 1 > upbound) throw out_of_bound(__LINE__);
        *(uint16_t *) len_ptr = htons(new_ptr - ptr);
        ptr = new_ptr;
    }
  }
  for (auto &add : additionals) {
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.name;
    ptr++;
    htons_ptr(ptr, add.Type, upbound);
    htons_ptr(ptr, add.playload_size, upbound);
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.high_bit_in_extend_rcode;
    ptr++;
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.edns0_verion;
    ptr++;
    htons_ptr(ptr, add.Z, upbound);
    htons_ptr(ptr, add.data_length, upbound);
  }

  return ptr - buf;
}

bool deep_find(Cache::Item *p, std::vector<Dns::Answer> &res_anss,
               Cache &cache, Dns::QType type, struct timespec &time) {
  bool found = false;
  for (auto &r : p->child_relations) {
    if (r->type == type) {
      Dns::Answer ans;
      ans.name = p->name;
      ans.Type = r->type;
      ans.rdata = r->child_item->name;
      ans.Class = Dns::IN;
      long ttl = r->exp_time - time.tv_sec;
      if (ttl < 1) {
        c_timeout = true;
        continue;
      } else ans.TTL = ttl;
      found = true;
      res_anss.insert(res_anss.begin(), ans);
    } else if (r->type == Dns::CNAME) {
      if (deep_find(r->child_item, res_anss, cache, type, time)) {
        Dns::Answer ans;
        ans.name = p->name;
        ans.Type = r->type;
        ans.rdata = r->child_item->name;
        ans.Class = Dns::IN;
        long ttl = r->exp_time - time.tv_sec;
        if (ttl < 1) {
          c_timeout = true;
          continue;
        } else ans.TTL = ttl;
        found = true;
        res_anss.insert(res_anss.begin(), ans);
      }
    }
  }
  return found;
}


Dns *Dns::make_response_by_cache(Dns &dns, Cache &cache) {
  std::vector<Answer> res_anss;
  auto &q = dns.questions[0];

  if (q.Type == Dns::A or q.Type == Dns::AAAA) {
    for (auto &item : Global::config->reserved_domains_mapping) {
      if ( item.first.second == q.Type and fnmatch(item.first.first.c_str(), q.name.c_str(), FNM_CASEFOLD) == 0) {
        // Match
        Dns *dns2 = new Dns();
        dns2->id = dns.id;
        dns2->signs = dns.signs;
        dns2->signs |= Dns::RA | Dns::QR;
        dns2->questions = dns.questions;
        Dns::Answer ans;
        ans.name = q.name;
        ans.Type = q.Type;
        ans.TTL = 600;
        ans.rdata = item.second;
        ans.Class = Dns::IN;
        dns2->answers.emplace_back(ans);
        return dns2;
      }
    }
  }

  Cache::Item *p = cache.getItem(q.name);
  if (p == nullptr) return nullptr;
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  c_timeout = false;

  if (deep_find(p, res_anss, cache, q.Type, time)) {
    Dns *dns2 = new Dns();
    dns2->id = dns.id;
    dns2->signs = dns.signs;
    dns2->signs |= Dns::RA | Dns::QR;
    dns2->questions = dns.questions;

    // shuffle the answers to realize the loadbalance
    unsigned seed = static_cast<unsigned int>(std::chrono::system_clock::now().time_since_epoch().count());
    for (auto iterator = res_anss.begin(); iterator != res_anss.end(); ++iterator) {
      if (iterator->Type == q.Type) {
        shuffle(iterator, res_anss.end(), std::default_random_engine(seed));
        break;
      }
    }

    dns2->answers = res_anss;
    return dns2;
  }
  if (c_timeout) {
    cache.timeout();
  }

  return nullptr;
}

// read the config file that contains the polluted domains
void Dns::load_polluted_domains(const std::string &config_filename) {
  polluted_domains.clear();
  std::ifstream fs;
  fs.open(config_filename);
  if (fs) {
    std::string line;
    while (!fs.eof()) {
      getline(fs, line);
      boost::algorithm::trim(line);
      if (!line.empty()) {
        if ('#' == line[0]) continue;
        if ('!' == line[0]) continue;
        polluted_domains.insert(line);
      }
    }
    fs.close();
    return;
  }
  std::cerr << "pollution file (" << config_filename << ") was not opened !" << std::endl;
}

bool Dns::isDomainValid(const std::string &domain) {
  static auto validDomainPattern = std::regex(
      R"(^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.$|\.))");
  return regex_match(domain, validDomainPattern);
}
