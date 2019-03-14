//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_DNS_H
#define DNSSTUB_DNS_H

#include <libnet.h>
#include <fnmatch.h>
#include <boost/algorithm/string.hpp>
#include <regex>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <iostream>
#include <boost/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/bimap/set_of.hpp>
#include <boost/bimap/list_of.hpp>
#include <boost/format.hpp>

class Cache;

inline std::string get_err_string(int num) {
  return (boost::format("__LINE__ %d") % num).str();
}


class out_of_bound : public std::runtime_error {
public:
  explicit out_of_bound(int line);
};

class BadDnsError : public std::runtime_error {
public:
  explicit BadDnsError(const std::string &__arg) : std::runtime_error(__arg) {}

  explicit BadDnsError(const char *__arg) : std::runtime_error(__arg) {}

  BadDnsError() : std::runtime_error("BadDnsError") {}
};




class Dns {

public:
  static std::unordered_set<std::string> polluted_domains;


  static bool isDomainValid(const std::string &domain);

  static void load_polluted_domains(const std::string &config_filename);

  enum Sign : uint16_t {
    QR = 1 << 15,
    OpCode = 1 << 14 & 1 << 13 & 1 << 12 & 1 << 11,
    AA = 1 << 10,
    TC = 1 << 9,
    RD = 1 << 8,
    RA = 1 << 7,
    AD = 1 << 5,
    CD = 1 << 4,
    RCODE = 1 << 3 & 1 << 2 & 1 << 1 & 1
  };

  enum QType : uint16_t {
    A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16,
    AAAA = 28, SRV = 33, NAPTR = 35, OPT = 41, IXPT = 251, AXFR = 252, ANY = 255
  };


  static boost::bimap<boost::bimaps::set_of<enum QType>, boost::bimaps::set_of<std::string>> QType2Name;

  enum QClass : uint16_t {
    IN = 1, NOCLASS = 254, ALL = 255
  };

  static std::unordered_map<enum QClass, std::string> QClass2Name;

  class Question {
  public:
    std::string name;
    enum QType Type;
    enum QClass Class;

    bool operator==(const Question &q) const {
      return this->name == q.name and this->Type == q.Type and this->Class == q.Class;
    }
  };

  class Answer {
  public:
    std::string name;
    enum QType Type;
    enum QClass Class;
    unsigned int TTL;
    std::string rdata;

  };

  class Additional {
  public:
    uint8_t name;
    uint16_t Type;
    uint16_t playload_size;
    uint8_t high_bit_in_extend_rcode;
    uint8_t edns0_verion;
    uint16_t Z;
    uint16_t data_length;
  };

  Dns(char buf[], int len) {
    from_wire(buf, len);
  }

  Dns() = default;

  void print();

  void from_wire(char buf[], int len);

  void set_opcode(unsigned short opcode) {
    signs = signs & ~OpCode;
    signs = signs & (opcode << 11);
  }

  unsigned short get_opcode() {
    return (signs & OpCode) >> 11;
  }

  void set_rcode(unsigned short rcode) {
    signs = signs & ~RCODE;
    signs = signs & rcode;
  }

  unsigned short get_rcode() {
    return (signs & RCODE);
  }

  ssize_t to_wire(char *buf, int len);

  std::vector<Question> questions;
  std::vector<Answer> answers;
  std::vector<Additional> additionals;


  std::string getName(char *&ptr, char *buf, const char *upbound);

  char *toName(std::string &name, char *ptr, const char *buf, const char *upbound,
               std::unordered_map<std::string, uint16_t> &str_map);

  unsigned short id{};
  unsigned short signs{};

  bool GFW_mode = true;

  bool use_localnet_dns_server = true;

  Dns *make_response_by_cache(Dns &dns, Cache &cache, struct sockaddr_storage &client_addr);

private:
  uint16_t ntohs_ptr(char *&ptr, const char *upbound) {
    if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
    uint16_t value = ntohs(*(uint16_t *) ptr);
    ptr += 2;
    return value;
  }

  uint32_t ntohl_ptr(char *&ptr, const char *upbound) {
    if (ptr + 3 > upbound) throw out_of_bound(__LINE__);
    uint32_t value = ntohl(*(uint32_t *) ptr);
    ptr += 4;
    return value;
  }

  void htons_ptr(char *&ptr, uint16_t value, const char *upbound) {
    if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
    *(uint16_t *) ptr = htons(value);
    ptr += 2;
  }

  void htonl_ptr(char *&ptr, uint32_t value, const char *upbound) {
    if (ptr + 3 > upbound) throw out_of_bound(__LINE__);
    *(uint32_t *) ptr = htonl(value);
    ptr += 4;
  }


  void checkLocalnetType();
};




#endif //DNSSTUB_DNS_H
