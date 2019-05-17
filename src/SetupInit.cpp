//
// Created by xiamr on 5/16/19.
//


#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <sys/timerfd.h>

#include <boost/log/trivial.hpp>

#include <boost/program_options.hpp>
#include <boost/checked_delete.hpp>

#include <boost/log/trivial.hpp>

#include <boost/format.hpp>

#include <boost/assert.hpp>

#include <tuple>

#include "Config.h"
#include "Global.h"
#include "DnsQueryStatistics.h"
#include "Cache.h"
#include "DnsHandler.hpp"
#include "SetupLog.hpp"





std::tuple<int,int,int, int , DnsQueryStatistics*> init(int argc, char *argv[]){
  const char *remote_address = nullptr;
  const char *localnet_server_address = nullptr;

  std::string config_filename = Global::parseArguments(argc, argv);

  config = Config::load_config_file(config_filename);
  if (!config) {
    std::cerr << "Error load config file" << std::endl;
    exit(EXIT_FAILURE);
  }

  Global::config = config;

  if (Global::debugMode) config->current_severity = boost::log::trivial::debug;
  boost_log_init(config);

  remote_address = config->remote_server_address.c_str();
  localnet_server_address = config->localnet_server_address.c_str();

  bDaemon = config->daemonMode;

  Dns::load_polluted_domains(config->polution);


  BOOST_LOG_TRIVIAL(info) << "Start Server ...";

  if (bDaemon) {
    BOOST_LOG_TRIVIAL(info) << "Enter daemon mode ..";
    daemon(0, 0);
  }


  for (auto &local : config->locals) {
    auto s = new SocketUnit;
    if (inet_pton(AF_INET6, local.address.c_str(), &((sockaddr_in6 *) &(s->addr))->sin6_addr)) {
      s->addr.ss_family = AF_INET6;
      ((sockaddr_in6 *) &(s->addr))->sin6_port = htons(local.port);
    } else if (inet_pton(AF_INET, local.address.c_str(), &((sockaddr_in *) &(s->addr))->sin_addr)) {
      s->addr.ss_family = AF_INET;
      ((sockaddr_in *) &(s->addr))->sin_port = htons(local.port);
    } else {
      BOOST_LOG_TRIVIAL(fatal) << "Local addresss is invaild : " << local.address;
      exit(EXIT_FAILURE);
    }

    if (s->addr.ss_family == AF_INET) {
      BOOST_LOG_TRIVIAL(info) << boost::format("listen at %s:%d") % local.address % local.port;
    } else {
      BOOST_LOG_TRIVIAL(info) << boost::format("listen at [%s]:%d") % local.address % local.port;
    }

    s->socket = socket(s->addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (s->socket < 0) {
      BOOST_LOG_TRIVIAL(fatal) << "Can not open socket for listening...  " << strerror(errno);
      exit(EXIT_FAILURE);
    }
    if (bind(s->socket, (sockaddr *) &(s->addr), sizeof(s->addr)) == -1) {
      BOOST_LOG_TRIVIAL(fatal) << boost::format("Can not bind port(%d) for listening") % local.port;
      exit(EXIT_FAILURE);
    }
    if (config->enableTcp) {
      s->socket_tcp = socket(s->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
      if (s->socket_tcp < 0) {
        BOOST_LOG_TRIVIAL(fatal) << "Can not open socket for listening...  " << strerror(errno);
        exit(EXIT_FAILURE);
      }
      if (bind(s->socket_tcp, (sockaddr *) &(s->addr), sizeof(s->addr)) == -1) {
        BOOST_LOG_TRIVIAL(fatal) << boost::format("Can not bind port(%d) for listening") % local.port;
        exit(EXIT_FAILURE);
      }
      if (listen(s->socket_tcp, 10) < 0) {
        BOOST_LOG_TRIVIAL(fatal) << "listen failed ! " << strerror(errno);
        exit(EXIT_FAILURE);
      }
      tcp_server_set.emplace(s->socket_tcp);
    }
    serverSockets.emplace_back(s);
    udp_server_map[s->socket] = s;
  }


  bzero(&upserver_addr, sizeof(upserver_addr));

  if (inet_pton(AF_INET6, remote_address, &((sockaddr_in6 *) &upserver_addr)->sin6_addr)) {
    upserver_addr.ss_family = AF_INET6;
    ((sockaddr_in6 *) &upserver_addr)->sin6_port = htons(config->remote_server_port);
  } else if (inet_pton(AF_INET, remote_address, &((sockaddr_in *) &upserver_addr)->sin_addr)) {
    upserver_addr.ss_family = AF_INET;
    ((sockaddr_in *) &upserver_addr)->sin_port = htons(config->remote_server_port);
  } else {
    BOOST_LOG_TRIVIAL(fatal) << boost::format("Remote addresss(%s) is invaild") % remote_address;
    exit(EXIT_FAILURE);
  }
  upserver_sock = socket(upserver_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  if (upserver_sock < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "Can not open socket remote up stream " << strerror(errno);
    exit(EXIT_FAILURE);
  }

  BOOST_LOG_TRIVIAL(info) << "remote upstream   -> " <<
                          (upserver_addr.ss_family == AF_INET6 ? boost::format("[%s]:%d") : boost::format("%s:%d"))
                          % config->remote_server_address % config->remote_server_port;

  bzero(&localnet_server_addr, sizeof(localnet_server_addr));

  if (inet_pton(AF_INET6, localnet_server_address, &((sockaddr_in6 *) &localnet_server_addr)->sin6_addr)) {
    localnet_server_addr.ss_family = AF_INET6;
    ((sockaddr_in *) &localnet_server_addr)->sin_port = htons(config->localnet_server_port);
  } else if (inet_pton(AF_INET, localnet_server_address, &((sockaddr_in *) &localnet_server_addr)->sin_addr)) {
    localnet_server_addr.ss_family = AF_INET;
    ((sockaddr_in *) &localnet_server_addr)->sin_port = htons(config->localnet_server_port);
  } else {
    BOOST_LOG_TRIVIAL(fatal) << "local net dns server address resolve error :" << localnet_server_address;
    exit(EXIT_FAILURE);
  }

  localnet_server_sock = socket(localnet_server_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

  if (localnet_server_sock < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "Can not open socket for localnet dns server :" << strerror(errno);
    exit(EXIT_FAILURE);
  }

  BOOST_LOG_TRIVIAL(info) << "localNet upstream -> "
                          << (localnet_server_addr.ss_family == AF_INET6 ?
                              boost::format("[%s]:%d") : boost::format("%s:%d"))
                             % config->localnet_server_address % config->localnet_server_port;

  if (!config->suUsername.empty()) {
    struct passwd *pass = getpwnam(config->suUsername.c_str());
    if (pass) {
      setgid(pass->pw_gid);
      setuid(pass->pw_uid);
    }
  }


  struct epoll_event ev{};
  int epollfd;
  epollfd = epoll_create1(EPOLL_CLOEXEC);

  for (auto &serverSocket : serverSockets) {
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = serverSocket->socket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, serverSocket->socket, &ev);

    if (config->enableTcp) {
      ev.events = EPOLLIN | EPOLLET;
      ev.data.fd = serverSocket->socket_tcp;
      epoll_ctl(epollfd, EPOLL_CTL_ADD, serverSocket->socket_tcp, &ev);
    }
  }


  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = upserver_sock;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, upserver_sock, &ev);

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = localnet_server_sock;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, localnet_server_sock, &ev);

  tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (tfd == -1) {
    BOOST_LOG_TRIVIAL(fatal) << "tfd  : " << strerror(errno);
    exit(EXIT_FAILURE);
  }
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = tfd;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, tfd, &ev);

  int cache_tfd{};
  if (config->enableCache) {
    cache_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = cache_tfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, cache_tfd, &ev);
    cache.set_timer_fd(cache_tfd);

  }

  // ignore SIGPIPE to avoid program exit when write to socket whose reading end is closed
  signal(SIGPIPE, SIG_IGN);

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);

  // signal of reload configuration file
  sigaddset(&mask, SIGUSR1);

  // signal of print statistics infomation
  sigaddset(&mask, SIGUSR2);

  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    BOOST_LOG_TRIVIAL(fatal) << "sigprocmask " << strerror(errno);
    exit(EXIT_FAILURE);
  }
  int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
  if (sfd == -1) {
    BOOST_LOG_TRIVIAL(fatal) << "signalfd " << strerror(errno);
    exit(EXIT_FAILURE);
  }
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = sfd;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, sfd, &ev);


  itimer.it_interval.tv_nsec = 0;
  itimer.it_interval.tv_sec = 0;



  return std::make_tuple(epollfd, cache_tfd, tfd,  sfd, new DnsQueryStatistics(config->statisticsFile));
}