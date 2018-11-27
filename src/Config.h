//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_CONFIG_H
#define DNSSTUB_CONFIG_H

#include <string>

class Config {
  Config() = default;

public:
  std::string localAddress;
  uint16_t localPort;
  std::string suUsername;
  std::string statisticsFile;
  std::string polution;
  bool enableCache;
  bool enableTcp;
  bool ipv6First;
  bool gfwMode;
  bool daemonMode;

  std::string remote_server_address;
  uint16_t remote_server_port;

  std::string localnet_server_address;
  uint16_t localnet_server_port;


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

};


#endif //DNSSTUB_CONFIG_H
