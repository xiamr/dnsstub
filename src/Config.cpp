//
// Created by xiamr on 11/27/18.
//


#include <regex>
#include <fstream>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <pugixml.hpp>
#include "json.hpp"
#include "Config.h"


using json = nlohmann::json;

void Config::trimAll() {
  for (auto &local : locals){
    boost::trim(local.address);
  }

  boost::trim(suUsername);
  boost::trim(statisticsFile);
  boost::trim(polution);
  boost::trim(remote_server_address);
  boost::trim(localnet_server_address);
}

Config* Config::load_config_file(const std::string &config_filename) {
  Config *config = nullptr;
  if (regex_match(config_filename, std::regex(R"(.+\.json$)"))) {
    config = load_json_config(config_filename);
  } else if (regex_match(config_filename, std::regex(R"(.+\.xml$)"))) {
    config = load_xml_config(config_filename);
  } else {
    std::cerr << "Error type of config file (either json or xml format)" << std::endl;
    exit(1);
  }
  return config;
}

Config* Config::load_xml_config(std::string filename) {
  pugi::xml_document doc;
  pugi::xml_parse_result result = doc.load_file(filename.c_str());

  if (!result) return nullptr;

  auto config = new Config();

  const pugi::xml_node &root = doc.child("config");

  //config->localAddress = root.child("localAddress").text().as_string();
  //config->localPort = root.child("localPort").text().as_int(53);

  for (auto &local : root.child("locals").children("local")){
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
  config->ipv6First = static_cast<IPv6Mode >(root.child("ipv6First").text().as_int(1));
  config->gfwMode = root.child("gfwMode").text().as_bool(false);
  config->daemonMode = root.child("daemonMode").text().as_bool(false);

  const pugi::xml_node &remote = root.child("remote_server");
  config->remote_server_address = remote.attribute("address").value();
  config->remote_server_port = remote.attribute("port").as_int(53);

  const pugi::xml_node &localnet = root.child("localnet_server");
  config->localnet_server_address = remote.attribute("address").value();
  config->localnet_server_port = remote.attribute("port").as_int(53);

  config->trimAll();

  return config;

}

Config* Config::load_json_config(std::string filename) {
  std::ifstream ifs;
  ifs.open(filename);
  if (!ifs.fail()) {
    json j;
    ifs >> j;

    auto config = new Config();
    try {
      for (auto& local : j["locals"]){
          config->locals.emplace_back(Local(local["address"],local["port"]));
      }
      config->suUsername = j.value("su", "");
      config->statisticsFile = j.value("statisticsFile", "");
      config->polution = j.value("pollution", "");

      config->enableCache = j.value("enableCache", false);
      config->enableTcp = j.value("enableTcp", false);
      switch (j.value("ipv6First", 1)){
        case 0: config->ipv6First = IPv6Mode::Off;
          break;
        case 1: config->ipv6First = IPv6Mode::OnlyForRemote;
          break;
        case 2: config->ipv6First = IPv6Mode::Full;
          break;
        default:
          std::cerr << "err type number of ipv6First mode" << std::endl;
          return nullptr;
      }
      config->gfwMode = j.value("gfwMode", false);
      config->daemonMode = j.value("daemonMode", false);


      const json &remote = j["remote_server"];
      config->remote_server_address = remote.value("address", "8.8.8.8");
      config->remote_server_port = remote.value("port", 53);

      const json &localnet = j["localnet_server"];
      config->localnet_server_address = localnet.value("address", "");
      config->localnet_server_port = localnet.value("port", 53);

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

