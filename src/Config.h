//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_CONFIG_H
#define DNSSTUB_CONFIG_H

#include <string>
#include <utility>
#include <boost/log/trivial.hpp>
#include <boost/bimap.hpp>
#include <netinet/in.h>

#include "config.h"

#include "Dns.h"

class Config {
  Config() = default;

public:

  enum class IPv6Mode {
    Off = 0,
    OnlyForRemote = 1,
    Full = 2,
    OnlyForLocal = 3
  };

  struct Local {
    std::string address;

    Local(const std::string &address, uint16_t port) : address(address), port(port) {}

    uint16_t port;

  };

  std::vector<struct Local> locals;
  std::string suUsername;
  std::string statisticsFile;
  std::string polution;
  bool enableCache;
  bool enableTcp;
  IPv6Mode ipv6First;
  bool gfwMode;
  bool daemonMode;

  std::string remote_server_address;
  uint16_t remote_server_port;

  std::string localnet_server_address;
  uint16_t localnet_server_port;

  boost::log::trivial::severity_level current_severity;

  class DnsRecord {
  public:
    std::string address;

    struct Scope {
      //scope
      sa_family_t scope_ss_family;

      union {
        struct in_addr addr;
        struct in6_addr addr6;
      } scope_addr;

      union {
        struct in_addr mask;
        struct in6_addr mask6;
      } scope_mask;

    };

    std::vector<struct Scope> scopes;

    bool match(struct sockaddr_storage &client_addr);

  };

  struct pairhash {
  public:
    template<typename T, typename U>
    std::size_t operator()(const std::pair<T, U> &x) const {
      return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
    }
  };

  std::unordered_map<std::pair<std::string, Dns::QType>, DnsRecord, pairhash> reserved_domains_mapping;


  /**
   * factory method to new an instance
   * @param config_filename  [json or xml format]
   * @return
   */
  static Config *load_config_file(const std::string &config_filename);

private:
#ifdef ENABLE_XML
  static Config *load_xml_config(const std::string &filename);
#endif

  static Config *load_json_config(const std::string &filename);

  void trimAll();

  static std::unordered_map<std::string, boost::log::trivial::severity_level> severity_level_map;
};


#endif //DNSSTUB_CONFIG_H
