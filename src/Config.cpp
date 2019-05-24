//
// Created by xiamr on 11/27/18.
//


#include <regex>
#include <fstream>
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include "config.h"

#ifdef ENABLE_XML

#include <pugixml.hpp>

#endif

#include <endian.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "json.hpp"
#include "Config.h"


using json = nlohmann::json;

std::unordered_map<std::string, boost::log::trivial::severity_level> Config::severity_level_map = {
    {boost::log::trivial::to_string(boost::log::trivial::trace),   boost::log::trivial::trace},
    {boost::log::trivial::to_string(boost::log::trivial::debug),   boost::log::trivial::debug},
    {boost::log::trivial::to_string(boost::log::trivial::info),    boost::log::trivial::info},
    {boost::log::trivial::to_string(boost::log::trivial::warning), boost::log::trivial::warning},
    {boost::log::trivial::to_string(boost::log::trivial::error),   boost::log::trivial::error},
    {boost::log::trivial::to_string(boost::log::trivial::fatal),   boost::log::trivial::fatal}
};

std::unordered_map<std::string, Config::IPv6Mode> Config::ipv6mode_map = {
    {"Off",           Config::IPv6Mode::Off},
    {"OnlyForLocal",  Config::IPv6Mode::OnlyForLocal},
    {"OnlyForRemote", Config::IPv6Mode::OnlyForRemote},
    {"Full",          Config::IPv6Mode::Full},
};

void Config::trimAll() {
  for (auto &local : locals) {
    boost::trim(local.address);
  }

  boost::trim(suUsername);
  boost::trim(statisticsFile);
  boost::trim(polution);
  boost::trim(remote_server_address);
  boost::trim(localnet_server_address);
}

Config *Config::load_config_file(const std::string &config_filename) {
  Config *config = nullptr;
  if (regex_match(config_filename, std::regex(R"(.+\.json$)"))) {
    config = load_json_config(config_filename);

#ifdef ENABLE_XML
  } else if (regex_match(config_filename, std::regex(R"(.+\.xml$)"))) {
    config = load_xml_config(config_filename);
#endif

  } else {
    std::cerr << "Error type of config file (either json "

                 #ifdef ENABLE_XML
                 "or xml"
                 #endif
                 " format)" << std::endl;
    exit(1);
  }
  return config;
}


void fill_scope(Config::DnsRecord &dnsRecord, const std::string &scope_str) {

  Config::DnsRecord::Scope scope;
  if (scope_str.empty()) {
    return;
  }
  std::vector<std::string> results;
  boost::split(results, scope_str, boost::is_any_of("/"));
  if (results.size() > 0) {
    std::string addr = results.front();

    if (inet_pton(AF_INET, addr.c_str(), reinterpret_cast<void *>(&scope.scope_addr.addr))) {
      scope.scope_ss_family = AF_INET;
      int number;
      if (results.size() == 1)
        number = 32;
      else {
        try {
          number = boost::lexical_cast<int>(results[1].c_str());
        } catch (boost::bad_lexical_cast &e) {
          std::cerr << "mask length must be a integer: " << e.what() << std::endl;
          exit(4);
        }
      }

      if (number < 0 or number > 32) {
        std::cerr << "wrong mask length : " << number << std::endl;
        exit(4);
      }
      scope.scope_mask.mask.s_addr = INADDR_ANY;
      uint32_t mask_number = 0;
      while (number) {
        mask_number += 1U << (32 - number);
        number--;
      }
      scope.scope_mask.mask.s_addr = htonl(mask_number);
      scope.scope_addr.addr.s_addr &= scope.scope_mask.mask.s_addr;

    } else if (inet_pton(AF_INET6, addr.c_str(), reinterpret_cast<void *>(&scope.scope_addr.addr6))) {
      scope.scope_ss_family = AF_INET6;
      int number;
      if (results.size() == 1)
        number = 128;
      else {
        try {
          number = boost::lexical_cast<int>(results[1].c_str());
        } catch (boost::bad_lexical_cast &e) {
          std::cerr << "mask length must be a integer: " << e.what() << std::endl;
          exit(4);
        }

      }

      if (number < 0 or number > 128) {
        std::cerr << "wrong mask length (must in the range of 0-128): " << number << std::endl;
        exit(4);
      }
      scope.scope_mask.mask6 = in6addr_any;
      uint64_t mask_number_high = 0;
      uint64_t mask_number_low = 0;
      while (number) {
        if (number <= 64) {
          mask_number_high += 1UL << (64 - number);
        } else {
          mask_number_low += 1UL << (128 - number);
//          std::cout << boost::format("%x") % mask_number_low << std::endl;
        }
        number--;
      }
      *((uint64_t * ) & scope.scope_mask.mask6.s6_addr) = htobe64(mask_number_high);
      *((uint64_t * )(scope.scope_mask.mask6.s6_addr + 8)) = htobe64(mask_number_low);
//      std::cout << mask_number_high << "  " << mask_number_low << std::endl;

    } else {
      std::cerr << "wrong address : " << results.front() << std::endl;
      exit(3);
    }
  }

#ifndef NDEBUG
  char addr[128];
  switch (scope.scope_ss_family) {
    case AF_INET:
      inet_ntop(AF_INET, reinterpret_cast<void *>(&scope.scope_addr.addr), addr, 128);
      std::cout << "addr : " << addr;
      inet_ntop(AF_INET, reinterpret_cast<void *>(&scope.scope_mask.mask), addr, 128);
      std::cout << "  mask : " << addr << std::endl;

  }
#endif

  dnsRecord.scopes.push_back(scope);
}

#ifdef ENABLE_XML

Config *Config::load_xml_config(const std::string &filename) {


  pugi::xml_document doc;
  pugi::xml_parse_result result = doc.load_file(filename.c_str());

  if (!result) return nullptr;

  auto config = new Config();

  const pugi::xml_node &root = doc.child("config");

  //config->localAddress = root.child("localAddress").text().as_string();
  //config->localPort = root.child("localPort").text().as_int(53);

  for (auto &local : root.child("locals").children("local")) {
    config->locals.emplace_back(Local(local.attribute("address").value(), local.attribute("port").as_int(53)));
  }


  const pugi::xml_node &su = root.child("su");
  if (!su.empty()) {
    config->suUsername = su.text().as_string();
  }

  const pugi::xml_node &statstics = root.child("statisticsFile");
  if (!statstics.empty()) config->statisticsFile = statstics.text().as_string();


  const pugi::xml_node &polution = root.child("pollution");
  if (!polution.empty()) config->polution = polution.text().as_string();


  config->enableCache = root.child("enableCache").text().as_bool(false);
  config->enableTcp = root.child("enableTcp").text().as_bool(false);

  try {
    config->ipv6First = Config::ipv6mode_map.at(boost::trim_copy(std::string(root.child("ipv6First").text().as_string("Off"))));
  } catch (std::out_of_range &e) {
    std::cerr << "Unkown ipv6First Mode : " << e.what() << std::endl;
    exit(EXIT_FAILURE);
  }


  if (auto ipv6FirstExceptIter = root.child("ipv6FirstExcept"); !ipv6FirstExceptIter.empty()) {
    for (auto &domain : ipv6FirstExceptIter.children("domain")) {
      std::string domain_str = domain.text().as_string();
      boost::trim(domain_str);
      if (!domain_str.empty()) config->ipv6FirstExcept.insert(domain_str);
    }
  }

  config->gfwMode = root.child("gfwMode").text().as_bool(false);
  config->daemonMode = root.child("daemonMode").text().as_bool(false);

  std::string severity = root.child("severity").text().as_string("info");
  auto node_iterator = severity_level_map.find(severity);
  if (node_iterator == severity_level_map.end()) {
    std::cerr << "error severity level : " << severity << std::endl;
    exit(EXIT_FAILURE);
  } else {
    config->current_severity = node_iterator->second;
  }


  const pugi::xml_node &remote = root.child("remote_server");
  config->remote_server_address = remote.attribute("address").value();
  config->remote_server_port = remote.attribute("port").as_int(53);

  const pugi::xml_node &localnet = root.child("localnet_server");
  config->localnet_server_address = localnet.attribute("address").value();
  config->localnet_server_port = localnet.attribute("port").as_int(53);

  auto mappings = root.child("mappings");
  if (!mappings.empty()) {
    for (auto &mapping : mappings.children("mapping")) {
      std::string type_str = mapping.attribute("type").value();
      std::string domain_str = mapping.attribute("domain").value();
      DnsRecord dnsRecord;
      dnsRecord.address = mapping.attribute("address").value();

      auto scopes = mapping.child("scopes");
      if (!scopes.empty()) {
        for (auto scope : scopes.children("scope")) {
          std::string scope_str = scope.text().as_string();
          boost::trim(scope_str);
          if (scope_str.empty()) {
            std::cerr << "scope is empty\n";
            exit(EXIT_FAILURE);
          }
          fill_scope(dnsRecord, scope_str);
        }
      }

      config->reserved_domains_mapping[
          std::make_pair(domain_str, Dns::QType2Name.right.find(type_str)->second)] = dnsRecord;
    }

  }


  config->trimAll();

  return config;

}

#endif

Config *Config::load_json_config(const std::string &filename) {
  std::ifstream ifs;
  ifs.open(filename);
  if (!ifs.fail()) {
    json j;
    ifs >> j;

    auto config = new Config();
    try {
      for (auto &local : j["locals"]) {
        config->locals.emplace_back(Local(local["address"], local["port"]));
      }
      config->suUsername = j.value("su", "");
      config->statisticsFile = j.value("statisticsFile", "");
      config->polution = j.value("pollution", "");

      config->enableCache = j.value("enableCache", false);
      config->enableTcp = j.value("enableTcp", false);
      try {
        config->ipv6First = Config::ipv6mode_map.at(boost::trim_copy(std::string(j.value("ipv6First", "Off"))));
      } catch (std::out_of_range &e) {
        std::cerr << "Unkown ipv6First Mode : " << e.what() << std::endl;
        exit(EXIT_FAILURE);
      }

      auto it = j.find("ipv6FirstExcept");
      if (it != j.end()) {
        for (auto &domain : *it) {
          std::string domain_str = domain;
          config->ipv6FirstExcept.insert(domain_str);
        }
      }


      config->gfwMode = j.value("gfwMode", false);
      config->daemonMode = j.value("daemonMode", false);

      std::string severity = j.value("severity", "info");

      auto node_iterator = severity_level_map.find(severity);
      if (node_iterator == severity_level_map.end()) {
        std::cerr << "error severity level : " << severity << std::endl;
        exit(EXIT_FAILURE);
      } else {
        config->current_severity = node_iterator->second;
      }

      const json &remote = j["remote_server"];
      config->remote_server_address = remote.value("address", "8.8.8.8");
      config->remote_server_port = remote.value("port", 53);

      const json &localnet = j["localnet_server"];
      config->localnet_server_address = localnet.value("address", "");
      config->localnet_server_port = localnet.value("port", 53);


      it = j.find("mappings");
      if (it != j.end()) {
        for (auto &item : *it) {
          std::string type_str = item["type"];
          DnsRecord dnsRecord;
          dnsRecord.address = item["address"];

          auto scopes_it = item.find("scopes");

          if (scopes_it != item.end()) {
            for (std::string scope_str : *scopes_it) {
              boost::trim(scope_str);
              fill_scope(dnsRecord, scope_str);
            }
          }
          config->reserved_domains_mapping[std::make_pair(item["domain"],
                                                          Dns::QType2Name.right.find(
                                                              type_str)->second)] = dnsRecord;
        }
      }
    } catch (nlohmann::detail::exception &exception) {
      std::cerr << exception.what() << std::endl;
      delete config;
      return nullptr;
    }
    config->trimAll();
    return config;
  }
  return nullptr;
}


bool Config::DnsRecord::match(struct sockaddr_storage &client_addr) {
#ifndef NDEBUG
  char addr[128];
  switch (client_addr.ss_family) {
    case AF_INET:
      inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(&client_addr)->sin_addr, addr, 128);
      break;
    case AF_INET6:
      inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&client_addr)->sin6_addr, addr, 128);
      break;
  }
  std::cout << "cliaddr : " << addr << std::endl;
#endif

  for (auto &scope : scopes) {
    switch (scope.scope_ss_family) {
      case AF_INET:
        if (client_addr.ss_family == AF_INET6) {
          if (IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<sockaddr_in6 *>(&client_addr)->sin6_addr)) {
            if ((*reinterpret_cast<uint32_t *>(reinterpret_cast<sockaddr_in6 *>(
                                                   &client_addr)->sin6_addr.s6_addr + 12) &
                 scope.scope_mask.mask.s_addr) == scope.scope_addr.addr.s_addr) {
              return true;
            }
          }
        } else if (client_addr.ss_family == AF_INET) {
          if ((reinterpret_cast<sockaddr_in *>(&client_addr)->sin_addr.s_addr & scope.scope_mask.mask.s_addr) ==
              scope.scope_addr.addr.s_addr)
            return true;
        }
        break;

      case AF_INET6:
        if (client_addr.ss_family == AF_INET6 and
            !IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<sockaddr_in6 *>(&client_addr)->sin6_addr)) {

          uint64_t high = *reinterpret_cast<uint64_t *>(reinterpret_cast<sockaddr_in6 *>(&client_addr)->sin6_addr.s6_addr);
          uint64_t low = *reinterpret_cast<uint64_t *>(
              reinterpret_cast<sockaddr_in6 *>(&client_addr)->sin6_addr.s6_addr + 8);

          uint64_t addr_high = *reinterpret_cast<uint64_t *>(scope.scope_addr.addr6.s6_addr);
          uint64_t addr_low = *reinterpret_cast<uint64_t *>(scope.scope_addr.addr6.s6_addr + 8);

          uint64_t mask_high = *reinterpret_cast<uint64_t *>(scope.scope_mask.mask6.s6_addr);
          uint64_t mask_low = *reinterpret_cast<uint64_t *>(scope.scope_mask.mask6.s6_addr + 8);


          if ((high & mask_high) == addr_high and (low & mask_low) == addr_low) {
            return true;
          }
        }
        break;
    }
  }
  return false;

}
