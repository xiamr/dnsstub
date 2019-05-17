//
// Created by xiamr on 5/16/19.
//

#ifndef DNSSTUB_DNSHANDLER_HPP
#define DNSSTUB_DNSHANDLER_HPP

#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/checked_delete.hpp>
#include <sys/epoll.h>
#include "Dns.h"
#include "Cache.h"

class Config;

extern bool bDaemon ;
extern Config *config;

struct SocketUnit {
  int socket = 0;
  int socket_tcp = 0;
  struct sockaddr_storage addr{};
};


inline uint16_t get_id() {
  static uint16_t id = 0;
  return id++;
}


class Upstream {
public:
  uint16_t cli_id;
  sockaddr_storage cliaddr;
  socklen_t socklen;
  bool checked_ipv6;
  bool ipv6_trun = false;
  Dns dns1;
  Upstream *prev, *next;
  struct timespec time;
  uint16_t up_id;
  int cli_fd;
  int ser_fd;
  char *buf = nullptr;
  ssize_t buf_len = 0;
  ssize_t data_len = 0;
  char len_buf[1];
  bool part_len = false;

  SocketUnit *s = nullptr;

  ~Upstream() {
    boost::checked_array_delete(buf);
  }
};

extern std::unordered_map<uint16_t, Upstream *> id_map;
extern Upstream *oldest_up, *newest_up;

extern struct itimerspec itimer;

extern int tfd;

extern std::unordered_map<int, Upstream *> client_tcp_con;
extern std::unordered_map<int, Upstream *> server_tcp_con;
extern struct sockaddr_storage upserver_addr;
extern struct sockaddr_storage localnet_server_addr;


extern int upserver_sock;
extern int localnet_server_sock;
extern Cache cache;
extern long last_timer;

extern std::vector<SocketUnit *> serverSockets;
extern std::unordered_map<int, SocketUnit *> udp_server_map;
extern std::unordered_set<int> tcp_server_set;

class DnsQueryStatistics;

void acceptTcpIncome(int server_sock_tcp, int epollfd, sockaddr_storage &cliaddr, socklen_t &socklen, epoll_event &ev);
void readServerResponse(int server_sock, char *buf);
void readIncomeQuery(int server_sock, char *buf, sockaddr_storage &cliaddr, socklen_t &socklen,
                     DnsQueryStatistics &statistics);
void readIncomeTcpQuery(int epollfd, char *buf, struct epoll_event event, DnsQueryStatistics &statistics);
void HandleServerSideTcp(int epollfd, char *buf, struct epoll_event event);
bool signalHandler(int sfd, DnsQueryStatistics &statistics);
void reqMessageTimeoutHandler();


#endif //DNSSTUB_DNSHANDLER_HPP
