//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_CONFIG_H
#define DNSSTUB_CONFIG_H

#include <string>
#include <boost/log/trivial.hpp>
#include <boost/bimap.hpp>

class Config {
  Config() = default;

public:

  enum class IPv6Mode {
    Off = 0,
    OnlyForRemote = 1,
    Full = 2
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


  /**
   * factory method to new an instance
   * @param config_filename  [json or xml format]
   * @return
   */
  static Config* load_config_file(const std::string &config_filename);

private:
  static Config* load_xml_config(std::string filename);
  static Config* load_json_config(std::string filename);
  void trimAll();

  static std::unordered_map<std::string, boost::log::trivial::severity_level> severity_level_map;
};


#endif //DNSSTUB_CONFIG_H
