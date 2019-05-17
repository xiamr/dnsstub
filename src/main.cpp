#include "config.h"

#include <utility>
#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <vector>
#include <tuple>
#include <list>
#include <map>
#include <unordered_map>
#include <sys/epoll.h>
#include <fcntl.h>

#include <unistd.h>
#include <pwd.h>
#include <sstream>

#include <unordered_set>
#include <functional>

#include <boost/log/trivial.hpp>

#include "Global.h"
#include "Config.h"
#include "DnsQueryStatistics.h"
#include "DnsHandler.hpp"
#include "SetupInit.hpp"



int main(int argc, char *argv[]) {

  Global::printVersionInfos();

  auto [epollfd, cache_tfd, tfd,  sfd, statistics] = init(argc, argv);


  struct epoll_event events[100],ev{};
  struct sockaddr_storage cliaddr;
  socklen_t socklen;
  char buf[max_udp_len];

  for (;;) {
    int nfds = epoll_wait(epollfd, events, 100, -1);
    for (int _n = 0; _n < nfds; ++_n) {
      if (udp_server_map.count(events[_n].data.fd)) {
        readIncomeQuery(events[_n].data.fd, buf, cliaddr, socklen, *statistics);
      } else if (events[_n].data.fd == upserver_sock) {
        readServerResponse(upserver_sock, buf);
      } else if (events[_n].data.fd == localnet_server_sock) {
        readServerResponse(localnet_server_sock, buf);
      } else if (Global::config->enableTcp and tcp_server_set.count(events[_n].data.fd)) {
        acceptTcpIncome(events[_n].data.fd, epollfd, cliaddr, socklen, ev);
      } else if (Global::config->enableTcp and client_tcp_con.find(events[_n].data.fd) != client_tcp_con.end()) {
        readIncomeTcpQuery(epollfd, buf, events[_n], *statistics);
      } else if (Global::config->enableTcp and server_tcp_con.find(events[_n].data.fd) != server_tcp_con.end()) {
        HandleServerSideTcp(epollfd, buf, events[_n]);
      } else if (Global::config->enableCache and events[_n].data.fd == cache_tfd) {
        BOOST_LOG_TRIVIAL(debug) << "cache time out";
        uint64_t exp;
        for (;;) {
          auto s = read(cache_tfd, &exp, sizeof(exp));
          if (s != sizeof(exp)) {
            if (errno == EAGAIN or errno == EWOULDBLOCK) {
              break;
            } else if (errno == EINTR) {
              continue;
            } else {
              BOOST_LOG_TRIVIAL(fatal) << "cache time fd : " << strerror(errno);
              exit(EXIT_FAILURE);
            }
          }
        }
        cache.timeout();
      } else if (events[_n].data.fd == tfd) {
        uint64_t exp;
        for (;;) {
          auto s = read(tfd, &exp, sizeof(exp));
          if (s != sizeof(exp)) {
            if (errno == EAGAIN or errno == EWOULDBLOCK) {
              break;
            } else if (errno == EINTR) {
              continue;
            } else {
              BOOST_LOG_TRIVIAL(fatal) << "req time fd : " << strerror(errno);
              exit(EXIT_FAILURE);
            }
          }
        }
        reqMessageTimeoutHandler();
      } else if (events[_n].data.fd == sfd) {
        // need to check which signal was sent
        bool exitFlag = signalHandler(sfd, *statistics);
        if (exitFlag) {
          goto end;
        }

      }
    }
  }

  end:
  boost::checked_delete(config);
  close(epollfd);
  for (auto s : serverSockets) {
    close(s->socket);
    if (config->enableTcp) close(s->socket_tcp);
    boost::checked_delete(s);
  }
  close(upserver_sock);
  close(localnet_server_sock);
  boost::checked_delete(statistics);
  return EXIT_SUCCESS;
}







