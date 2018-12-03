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
#include <queue>
#include <fcntl.h>
#include <time.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sstream>
#include <signal.h>
#include <sys/signalfd.h>
#include <unordered_set>
#include <fstream>
#include <regex>
#include <functional>
#include <boost/algorithm/string.hpp>
#include <fmt/printf.h>
#include <algorithm>    // std::shuffle
#include <array>        // std::array
#include <random>       // std::default_random_engine
#include <chrono>       // std::chrono::system_clock
#include "json.hpp"
#include <boost/program_options.hpp>
#include <boost/checked_delete.hpp>

#include "Config.h"
#include "Global.h"
#include "Dns.h"
#include "DnsQueryStatistics.h"
#include "Cache.h"


#ifdef NDEBUG
#define DEBUG(str)
#else
#define DEBUG(str) std::cout << str << std::endl;
#endif

const int max_udp_len = 65536;
bool bDaemon = false;
Config *config = nullptr;

struct SocketUnit {
  int socket = 0;
  int socket_tcp = 0;
  struct sockaddr_storage addr{};
};


int setnonblocking(int fd) {
  int old_option = fcntl(fd, F_GETFL);
  if (old_option == -1) {
    perror("get file destionptor flags failed");
    exit(EXIT_FAILURE);
  }
  int new_option = old_option | O_NONBLOCK;
  if (fcntl(fd, F_SETFL, new_option) == -1) {
    perror("set nonblocking failed!");
    exit(EXIT_FAILURE);
  }
  return old_option;
}

uint16_t get_id() {
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

std::unordered_map<uint16_t, Upstream *> id_map;
Upstream *oldest_up = nullptr, *newest_up = nullptr;

struct itimerspec itimer;

int tfd;

std::unordered_map<int, Upstream *> client_tcp_con;
std::unordered_map<int, Upstream *> server_tcp_con;
struct sockaddr_storage upserver_addr;
struct sockaddr_storage localnet_server_addr;


int upserver_sock;
int localnet_server_sock;
Cache cache;
long last_timer = 0;

std::vector<SocketUnit *> serverSockets;
std::unordered_map<int, SocketUnit *> udp_server_map;
std::unordered_set<int> tcp_server_set;



bool add_upstream(char *buf, ssize_t n, Upstream *upstream) {
  if (upstream->dns1.questions.empty()) {
    boost::checked_delete(upstream);
    return false;
  }
  auto &q = upstream->dns1.questions[0];
  std::string ostr = fmt::sprintf("%s  %s    %s\n", q.name, Dns::QClass2Name[q.Class], Dns::QType2Name[q.Type]);

  std::cout << ostr;
  if (bDaemon) syslog(LOG_INFO, "%s", ostr.c_str());

  if (q.Type == Dns::A and (Config::IPv6Mode::Full == config->ipv6First or
                            (!upstream->dns1.use_localnet_dns_server ? Config::IPv6Mode::OnlyForRemote ==
                                                                       config->ipv6First : false))) {
    q.Type = Dns::AAAA;
    upstream->checked_ipv6 = false;
  } else {
    upstream->checked_ipv6 = true;
  }
  upstream->dns1.GFW_mode = config->gfwMode;

  upstream->cli_id = upstream->dns1.id;
  upstream->dns1.id = get_id();
  upstream->up_id = upstream->dns1.id;


  clock_gettime(CLOCK_MONOTONIC, &upstream->time);
  upstream->next = nullptr;
  upstream->prev = newest_up;
  newest_up = upstream;
  if (!oldest_up) {
    oldest_up = upstream;
    itimer.it_value.tv_sec = upstream->time.tv_sec + 60;
    itimer.it_value.tv_nsec = upstream->time.tv_nsec;
    if (itimer.it_value.tv_sec - last_timer > 60) {
      timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
      last_timer = itimer.it_value.tv_sec;
    }
  } else {
    upstream->prev->next = upstream;
  }
  id_map[upstream->up_id] = upstream;
  return true;
}

Upstream *check(char *buf, ssize_t &n, bool tcp) {
  uint16_t up_id = ntohs(*(uint16_t *) buf);
  auto it = id_map.find(up_id);
  if (it != id_map.end()) {
    Upstream *upstream = it->second;
    if (!upstream->prev and upstream->next) {
      oldest_up = upstream->next;
      oldest_up->prev = nullptr;
      itimer.it_value.tv_sec = oldest_up->time.tv_sec + 60; // 60 secs
      itimer.it_value.tv_nsec = oldest_up->time.tv_nsec;
      if (itimer.it_value.tv_sec - last_timer > 60) {
        timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
        last_timer = itimer.it_value.tv_sec;
      }
    } else if (!upstream->prev and !upstream->next) {
      oldest_up = newest_up = nullptr;
      itimer.it_value.tv_sec = 0;
      itimer.it_value.tv_nsec = 0;
      if (itimer.it_value.tv_sec - last_timer > 60) {
        timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
        last_timer = itimer.it_value.tv_sec;
      }
    } else if (upstream->prev and !upstream->next) {
      newest_up = upstream->prev;
      newest_up->next = nullptr;
    } else {
      upstream->prev->next = upstream->next;
      upstream->next->prev = upstream->prev;
    }
    Dns dns1;
    try {
      dns1.from_wire(buf, n);
    } catch (out_of_bound &err) {
      boost::checked_delete(upstream);
      return nullptr;
    } catch (BadDnsError &) {
      boost::checked_delete(upstream);
      return nullptr;
    }
    cache.construct(dns1);

    if (!upstream->checked_ipv6) {

      for (auto &ans : dns1.answers) {
        if (ans.Type == Dns::AAAA) {
          upstream->checked_ipv6 = true;

          break;
        }
      }
      if (!upstream->checked_ipv6 and dns1.signs & Dns::TC) upstream->ipv6_trun = true;

      if (upstream->checked_ipv6) {
        dns1.questions[0].Type = Dns::A;

        try {
          n = dns1.to_wire(buf, max_udp_len);
        } catch (out_of_bound &err) {
          std::cerr << "Memory Access Error : " << err.what() << std::endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          boost::checked_delete(upstream);
          return nullptr;
        }
      } else {
        if (!upstream->ipv6_trun) cache.noipv6_domain.insert(dns1.questions[0].name);
        upstream->checked_ipv6 = true;
        upstream->dns1.questions[0].Type = Dns::A;
        upstream->dns1.id = get_id();
        upstream->up_id = upstream->dns1.id;
        try {
          n = upstream->dns1.to_wire(buf, max_udp_len);
        } catch (out_of_bound &err) {
          std::cerr << "Memory Access Error : " << err.what() << std::endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          boost::checked_delete(upstream);
          return nullptr;
        }

        id_map.erase(it);

        if (tcp) {
          close(upstream->ser_fd);
          int upfd;
          upfd = socket(upserver_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
          if (upfd < 0) {
            perror("Can not open socket ");
            if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
            exit(EXIT_FAILURE);
          }
          struct epoll_event ev;
          ev.events = EPOLLET | EPOLLOUT | EPOLLRDHUP;
          ev.data.fd = upfd;
          int ret = connect(upfd, (sockaddr *) &upserver_addr, sizeof(upserver_addr));
          if (ret < 0 and errno != EINPROGRESS) {
            if (bDaemon) syslog(LOG_ERR, "connect failed %d : %s ", __LINE__, strerror(errno));
            return nullptr;
          }
          upstream->ser_fd = upfd;
          server_tcp_con[upfd] = upstream;
        } else {
          if (upstream->dns1.use_localnet_dns_server) {
            if (sendto(localnet_server_sock, buf, n, 0, (sockaddr *) &localnet_server_addr,
                       sizeof(localnet_server_addr)) < 0) {
              std::cerr << "send error : " << __LINE__ << strerror(errno) << std::endl;
              if (bDaemon)
                syslog(LOG_WARNING, "sendto up stream error %d : %s", __LINE__, strerror(errno));
            }
          } else if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr, sizeof(upserver_addr)) <
                     0) {
            std::cerr << "send error : " << __LINE__ << strerror(errno) << std::endl;
            if (bDaemon) syslog(LOG_WARNING, "sendto up stream error %d : %s", __LINE__, strerror(errno));
          }
          id_map[upstream->dns1.id] = upstream;
          upstream->next = nullptr;
          upstream->prev = newest_up;
        }

        id_map[upstream->dns1.id] = upstream;
        upstream->next = nullptr;
        upstream->prev = newest_up;
        clock_gettime(CLOCK_MONOTONIC, &upstream->time);
        newest_up = upstream;
        if (!oldest_up) {
          oldest_up = upstream;
          itimer.it_value.tv_nsec = itimer.it_value.tv_nsec;
          itimer.it_value.tv_sec = upstream->time.tv_sec + 60; // 60 secs
          if (itimer.it_value.tv_sec - last_timer > 60) {
            timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
            last_timer = itimer.it_value.tv_sec;
          }
        } else {
          upstream->prev->next = upstream;
        }
        id_map[upstream->dns1.id] = upstream;
        return nullptr;

      }
    } else {
      if (upstream->ipv6_trun) {
        dns1.answers.clear();
        dns1.signs |= Dns::TC;
        try {
          n = dns1.to_wire(buf, max_udp_len);
        } catch (out_of_bound &err) {
          std::cerr << "Memory Access Error : " << err.what() << std::endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          boost::checked_delete(upstream);
          return nullptr;
        }
      }
    }
    return upstream;
  }
  return nullptr;
}

void read_buf(int fd, char *buf, Upstream *up) {
  ssize_t n = 0;
  for (;;) {
    if (up->buf == nullptr) {
      if (up->part_len) {
        n = read(fd, buf + 1, 1);
        if (n < 0 and errno == EAGAIN) {
          break;
        } else if (n == 1) {
          up->part_len = false;
          buf[0] = up->len_buf[0];
          up->buf_len = ntohs(*(uint16_t *) buf);
          up->buf = new char[up->buf_len];
        } else {
          break;
        }
      } else {
        n = read(fd, buf, 2);
        if (n < 0 and errno == EAGAIN) {
          break;
        } else if (n == 2) {
          up->buf_len = ntohs(*(uint16_t *) buf);
          up->buf = new char[up->buf_len];
        } else if (n == 1) {
          up->part_len = true;
          up->len_buf[0] = buf[0];
        } else {
          break;
        }
      }
    } else {
      n = read(fd, up->buf + up->data_len, max_udp_len);
      if (n < 0 and errno == EAGAIN) {
        break;
      } else if (n == 0) {
        // End of stream
        break;
      } else {
        up->data_len += n;
      }
    }
  }
}


void acceptTcpIncome(int server_sock_tcp, int epollfd, sockaddr_storage &cliaddr, socklen_t &socklen, epoll_event &ev) {
  for (;;) {
    int newcon = accept4(server_sock_tcp, (sockaddr *) &cliaddr, &socklen, SOCK_NONBLOCK);
    if (newcon < 0) {
      if (errno != EAGAIN)
        perror("accept error :");
      if (bDaemon) syslog(LOG_WARNING, "accept error %d : %s", __LINE__, strerror(errno));
      break;
    }
    DEBUG("new tcp connection from client")
    // Accept new connnection from client
    ev.events = EPOLLET | EPOLLIN | EPOLLERR;
    ev.data.fd = newcon;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, newcon, &ev);
    auto *up = new Upstream();
    memcpy(&up->cliaddr, &cliaddr, socklen);
    up->socklen = socklen;
    up->cli_fd = newcon;
    client_tcp_con[newcon] = up;
  }
}

void readServerResponse(int server_sock, char *buf) {
  ssize_t n;
  while ((n = recv(server_sock, buf, max_udp_len, 0)) > 0) {
    DEBUG("recv udp response from dns server")
    auto upstream = check(buf, n, false);
    if (upstream == nullptr) continue;

    *(uint16_t *) buf = htons(upstream->cli_id);
    DEBUG("send udp response to client")
    sendto(upstream->s->socket, buf, n, 0, (sockaddr *) &upstream->cliaddr, upstream->socklen);
    id_map.erase(upstream->up_id);
    boost::checked_delete(upstream);
    upstream = nullptr;
  }
}


void readIncomeQuery(int server_sock, char *buf, sockaddr_storage &cliaddr, socklen_t &socklen,
                     DnsQueryStatistics &statistics) {
  ssize_t n;
  while ((n = recvfrom(server_sock, buf, 65536, 0, (sockaddr *) &cliaddr, &socklen)) > 0) {
    DEBUG("new udp request from client")

    auto up = new Upstream;
    try {
      up->dns1.from_wire(buf, n);
    } catch (out_of_bound &err) {
      std::cerr << "Memory Access Error : " << err.what() << std::endl;
      if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
    } catch (BadDnsError) {
      std::cerr << "Bad Dns " << std::endl;
    }
    if (up->dns1.questions.empty()) {
      boost::checked_delete(up);
      continue;
    }
    statistics.countNewQuery(up->dns1);
    Dns *response = nullptr;
    if (Config::IPv6Mode::Full == config->ipv6First or
        (!up->dns1.use_localnet_dns_server ? Config::IPv6Mode::OnlyForRemote ==
                                             config->ipv6First : false)) {
      if (up->dns1.questions[0].Type == Dns::A
          and !cache.noipv6_domain.count(up->dns1.questions[0].name)) {
        up->dns1.questions[0].Type = Dns::AAAA;
        response = up->dns1.make_response_by_cache(up->dns1, cache);
        if (response) response->questions[0].Type = Dns::A;
        up->dns1.questions[0].Type = Dns::A;
      } else {
        response = up->dns1.make_response_by_cache(up->dns1, cache);
      }
    } else {
      response = up->dns1.make_response_by_cache(up->dns1, cache);
    }
    if (response) {
      try {
        n = response->to_wire(buf, max_udp_len);
      } catch (out_of_bound &err) {
        std::cerr << "Memory Access Error : " << err.what() << std::endl;
        if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
      }
      DEBUG("send response to client from cache")
      sendto(server_sock, buf, n, 0, (sockaddr *) &cliaddr, socklen);
      boost::checked_delete(response);
      boost::checked_delete(up);
    } else {
      memcpy(&up->cliaddr, &cliaddr, socklen);
      up->socklen = socklen;
      up->s = udp_server_map[server_sock];
      if (!add_upstream(buf, n, up)) continue;
      if ((Config::IPv6Mode::Full == config->ipv6First or
           (!up->dns1.use_localnet_dns_server ? Config::IPv6Mode::OnlyForRemote ==
                                                config->ipv6First : false)) or config->gfwMode) {
        try {
          n = up->dns1.to_wire(buf, max_udp_len);
        } catch (out_of_bound &err) {
          std::cerr << "Memory Access Error : " << err.what() << std::endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
          boost::checked_delete(up);
          continue;
        }
      } else {
        *(uint16_t *) buf = htons(up->up_id);
      }
      DEBUG("send udp request to server")
      if (up->dns1.use_localnet_dns_server) {
        if (sendto(localnet_server_sock, buf, n, 0, (sockaddr *) &localnet_server_addr,
                   sizeof(localnet_server_addr)) <
            0) {
          std::cerr << "send error : " << __LINE__ << std::endl;
          if (bDaemon) syslog(LOG_WARNING, "sendto up stream error ");
        }
      } else if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr,
                        sizeof(upserver_addr)) < 0) {
        std::cerr << "send error  : " << __LINE__ << std::endl;
        if (bDaemon) syslog(LOG_WARNING, "sendto up stream error ");
      }
    }
  }
}

void readIncomeTcpQuery(int epollfd, char *buf, struct epoll_event event, DnsQueryStatistics &statistics) {
  // Read query request from tcp client
  ssize_t n;
  auto up = client_tcp_con[event.data.fd];
  if (event.events & EPOLLIN) {
    DEBUG("tcp request data from client")
    read_buf(event.data.fd, buf, up);
    if (up->data_len == up->buf_len != 0) {
      try {
        up->dns1.from_wire(up->buf, up->buf_len);
      } catch (out_of_bound &err) {
        std::cerr << "Memory Access Error : " << err.what() << std::endl;
        if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
      } catch (BadDnsError) {
        std::cerr << "Bad Dns " << std::endl;
      }
      if (up->dns1.questions.empty()) {
        boost::checked_delete(up);
        close(up->cli_fd);
        client_tcp_con.erase(up->cli_fd);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
        return;
      }
      statistics.countNewQuery(up->dns1);
      Dns *response = nullptr;
      if (Config::IPv6Mode::Full == config->ipv6First or
          (!up->dns1.use_localnet_dns_server ? Config::IPv6Mode::OnlyForRemote ==
                                               config->ipv6First : false)) {
        if (up->dns1.questions[0].Type == Dns::A and
            !cache.noipv6_domain.count(up->dns1.questions[0].name)) {
          up->dns1.questions[0].Type = Dns::AAAA;
          response = up->dns1.make_response_by_cache(up->dns1, cache);
          if (response) response->questions[0].Type = Dns::A;
          up->dns1.questions[0].Type = Dns::A;
        } else {
          response = up->dns1.make_response_by_cache(up->dns1, cache);
        }
      } else {
        response = up->dns1.make_response_by_cache(up->dns1, cache);
      }
      if (response) {
        try {
          n = response->to_wire(buf + 2, max_udp_len - 2);
        } catch (out_of_bound &err) {
          std::cerr << "Memory Access Error : " << err.what() << std::endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
        }
        *(uint16_t *) buf = htons(n);
        DEBUG("send tcp response to client from cache")
        write(up->cli_fd, buf, n + 2);
        close(up->cli_fd);
        client_tcp_con.erase(up->cli_fd);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
        boost::checked_delete(up);
        boost::checked_delete(response);

      } else {
        if (!add_upstream(up->buf, up->buf_len, up)) return;
        int upfd;

        if (up->dns1.use_localnet_dns_server) {
          upfd = socket(localnet_server_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        } else {
          upfd = socket(upserver_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        }
        if (upfd < 0) {
          perror("Can not open socket ");
          exit(2);
        }
        struct epoll_event ev;
        ev.events = EPOLLET | EPOLLOUT | EPOLLERR;
        ev.data.fd = upfd;
        epoll_ctl(epollfd, EPOLL_CTL_ADD, upfd, &ev);
        DEBUG("new tcp connnect to server")
        int ret;
        if (up->dns1.use_localnet_dns_server) {
          ret = connect(upfd, (sockaddr *) &localnet_server_addr, sizeof(localnet_server_addr));
          DEBUG("Tcp connect to localnet dns server ...")
        } else {
          ret = connect(upfd, (sockaddr *) &upserver_addr, sizeof(upserver_addr));
          DEBUG("Tcp connect to remote dns server ...")
        }
        if (ret < 0 and errno != EINPROGRESS) {
          syslog(LOG_ERR, "connect to up server error %d : %s", __LINE__, strerror(errno));
        }
        up->ser_fd = upfd;
        server_tcp_con[upfd] = up;
      }
    }
  } else if (event.events & EPOLLERR) {
    DEBUG("tcp connection errror. close it")
    close(event.data.fd);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, event.data.fd, nullptr);
    boost::checked_delete(up);
    client_tcp_con.erase(event.data.fd);
  }

}

void HandleServerSideTcp(int epollfd, char *buf, struct epoll_event event) {
  ssize_t n;
  int upfd = event.data.fd;
  auto *up = server_tcp_con[upfd];
  if (event.events & EPOLLOUT) {
    // Connect succeed!
    DEBUG("tcp connection established")

    n = up->dns1.to_wire(buf + 2, max_udp_len - 2);
    *(uint16_t *) buf = htons(n);
    DEBUG("send tcp request to server")
    ssize_t siz = write(upfd, buf, n + 2);
    if (siz != n + 2) {
      perror("up write ");
      return;
    }
    struct epoll_event ev;
    ev.events = EPOLLET | EPOLLIN | EPOLLERR;
    ev.data.fd = upfd;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, upfd, &ev);
    boost::checked_array_delete(up->buf);
    up->buf_len = up->data_len = 0;
    up->buf = nullptr;
    up->part_len = false;
  } else if (event.events & EPOLLIN) {
    read_buf(upfd, buf, up);
    if (up->data_len == up->buf_len and up->buf_len != 0) {
      DEBUG("recv tcp response from server")
      memcpy(buf + 2, up->buf, up->data_len);

      auto upstream = check(buf + 2, up->data_len, true);
      if (upstream == nullptr)
        return;
      *(uint16_t *) buf = htons(up->data_len);
      *(uint16_t *) (buf + 2) = htons(upstream->cli_id);
      DEBUG("send tcp response to client")
      write(upstream->cli_fd, buf, up->data_len + 2);
      close(upstream->cli_fd);
      close(upstream->ser_fd);
      client_tcp_con.erase(upstream->cli_fd);
      server_tcp_con.erase(upstream->ser_fd);
      epoll_ctl(epollfd, EPOLL_CTL_DEL, upstream->cli_fd, nullptr);
      epoll_ctl(epollfd, EPOLL_CTL_DEL, upstream->ser_fd, nullptr);
      id_map.erase(upstream->up_id);
      boost::checked_delete(upstream);
      upstream = nullptr;
    }
  } else if (event.events & EPOLLERR) {
    DEBUG("tcp connection error. close ...")
    close(up->cli_fd);
    close(up->ser_fd);
    client_tcp_con.erase(up->cli_fd);
    server_tcp_con.erase(up->ser_fd);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, up->ser_fd, nullptr);
    id_map.erase(up->up_id);
    boost::checked_delete(up);
  }
}

/**
 *
 * @param sfd
 * @return true means to exit the program
 */
bool signalHandler(int sfd, DnsQueryStatistics &statistics) {
  ssize_t ssize;
  struct signalfd_siginfo signalfdSiginfo;
  for (;;) {
    ssize = read(sfd, &signalfdSiginfo, sizeof(struct signalfd_siginfo));
    if (ssize != sizeof(struct signalfd_siginfo)) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      std::cerr << "signalfd read error " << std::endl;
      return false;
    }
    switch (signalfdSiginfo.ssi_signo) {
      case SIGUSR1:
        std::cout << "reloading config file <pollution_domains.config> ..." << std::endl;
        Dns::load_polluted_domains("pollution_domains.config");
        std::cout << "reload complete !" << std::endl;
        break;
      case SIGUSR2:
        statistics.printStatisticsInfos();
        break;
      case SIGTERM:
      case SIGINT:
        if (bDaemon) syslog(LOG_INFO, "exit normally");
        statistics.printStatisticsInfos();
        return true;
        break;
      default:
        std::cerr << "unexcepted signal (" << signalfdSiginfo.ssi_signo << ") " << std::endl;
    }
  }
  return false;
}

void reqMessageTimeoutHandler() {
  DEBUG("request data structure time out")
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  while (oldest_up) {
    if (oldest_up->time.tv_sec + 60 < now.tv_sec) {
      auto up = oldest_up;
      oldest_up = up->next;
      if (oldest_up) oldest_up->prev = nullptr;
      id_map.erase(up->up_id);
      client_tcp_con.erase(up->cli_fd);
      server_tcp_con.erase(up->ser_fd);
      if (up == newest_up) {
        newest_up = nullptr;
      }
      boost::checked_delete(up);
      up = nullptr;
    } else {
      break;
    }
  }
  if (oldest_up) {
    itimer.it_value.tv_sec = oldest_up->time.tv_sec + 60; // 60 secs
    itimer.it_value.tv_nsec = oldest_up->time.tv_nsec;
  } else {
    itimer.it_value.tv_sec = 0;
    itimer.it_value.tv_nsec = 0;
  }
  if (itimer.it_value.tv_sec - last_timer > 60) {
    timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
    last_timer = itimer.it_value.tv_sec;
  }
}


int main(int argc, char *argv[]) {

  Global::printVersionInfos();

  const char *remote_address = nullptr;
  const char *localnet_server_address = nullptr;

  std::string config_filename = Global::parseArguments(argc, argv);

  config = Config::load_config_file(config_filename);


  remote_address = config->remote_server_address.c_str();
  localnet_server_address = config->localnet_server_address.c_str();

  bDaemon = config->daemonMode;

  Dns::load_polluted_domains(config->polution);


  std::cout << "Start Server ..." << std::endl;
  if (bDaemon) {
    std::cout << "Enter daemon mode .." << std::endl;
    std::cout << "Open syslog facility .. " << std::endl;
    daemon(0, 0);
    openlog(argv[0], LOG_PID, LOG_USER);
  }



  for (auto &local : config->locals) {
    auto s = new SocketUnit;
    if (inet_pton(AF_INET6, local.address.c_str(), &((sockaddr_in *) &(s->addr))->sin_addr)) {
      s->addr.ss_family = AF_INET6;
      ((sockaddr_in6 *) &(s->addr))->sin6_port = htons(local.port);
    } else if (inet_pton(AF_INET, local.address.c_str(), &((sockaddr_in *) &(s->addr))->sin_addr)) {
      s->addr.ss_family = AF_INET;
      ((sockaddr_in *) &(s->addr))->sin_port = htons(local.port);
    } else {
      std::cerr << "Local addresss is invaild" << std::endl;
      exit(EXIT_FAILURE);
    }

    if (s->addr.ss_family == AF_INET) {
      std::cout << fmt::sprintf("listen at %s:%d\n", local.address, local.port);
    } else {
      std::cout << fmt::sprintf("listen at [%s]:%d\n", local.address, local.port);
    }

    s->socket = socket(s->addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (s->socket < 0) {
      perror("Can not open socket ");
      if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
      exit(EXIT_FAILURE);
    }
    if (bind(s->socket, (sockaddr *) &(s->addr), sizeof(s->addr)) == -1) {
      perror("bind failed !");
      if (bDaemon) syslog(LOG_ERR, "Can not bind port(%d) for listening", local.port);
      exit(EXIT_FAILURE);
    }
    if (config->enableTcp) {
      s->socket_tcp = socket(s->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
      if (s->socket_tcp < 0) {
        perror("Can not open socket ");
        if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
        exit(EXIT_FAILURE);
      }
      if (bind(s->socket_tcp, (sockaddr *) &(s->addr), sizeof(s->addr)) == -1) {
        perror("bind failed !");
        if (bDaemon) syslog(LOG_ERR, "Can not bind port(%d) for listening", local.port);
        exit(EXIT_FAILURE);
      }
      if (listen(s->socket_tcp, 10) < 0) {
        perror("listen failed !");

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
    std::cerr << "Remote addresss is invaild" << std::endl;
    if (bDaemon) syslog(LOG_ERR, "Remote addresss(%s) is invaild", remote_address);
    exit(EXIT_FAILURE);
  }
  upserver_sock = socket(upserver_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  if (upserver_sock < 0) {
    perror("Can not open socket ");
    if (bDaemon) syslog(LOG_ERR, "Can not open socket remote up stream server communication");
    exit(EXIT_FAILURE);
  }

  bzero(&localnet_server_addr, sizeof(localnet_server_addr));

  if (inet_pton(AF_INET6, localnet_server_address, &((sockaddr_in *) &localnet_server_addr)->sin_addr)) {
    localnet_server_addr.ss_family = AF_INET6;
    ((sockaddr_in *) &localnet_server_addr)->sin_port = htons(config->localnet_server_port);
  } else if (inet_pton(AF_INET, localnet_server_address, &((sockaddr_in *) &localnet_server_addr)->sin_addr)) {
    localnet_server_addr.ss_family = AF_INET;
    ((sockaddr_in *) &localnet_server_addr)->sin_port = htons(config->localnet_server_port);
  } else {
    std::cerr << "local net dns server address resolve error" << std::endl;
    exit(EXIT_FAILURE);
  }

  localnet_server_sock = socket(localnet_server_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

  if (localnet_server_sock < 0) {
    perror("Can not open socket for localnet dns server");
    exit(EXIT_FAILURE);
  }

  if (!config->suUsername.empty()) {
    struct passwd *pass = getpwnam(config->suUsername.c_str());
    if (pass) {
      setgid(pass->pw_gid);
      setuid(pass->pw_uid);
    }
  }

  struct sockaddr_storage cliaddr;
  socklen_t socklen;
  char buf[max_udp_len];
  ssize_t n;

  struct epoll_event ev, events[100];
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

  tfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (tfd == -1) {
    perror("tfd ");
    return EXIT_FAILURE;
  }
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = tfd;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, tfd, &ev);

  int cache_tfd;
  if (config->enableCache) {
    cache_tfd = timerfd_create(CLOCK_MONOTONIC, 0);
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

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    std::string ostr = fmt::sprintf("sigprocmask %s\n", strerror(errno));
    std::cerr << ostr;
    if (bDaemon) syslog(LOG_ERR, "%s", ostr.c_str());
    //exit(EXIT_FAILURE);
  }
  int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
  if (sfd == -1) {
    std::string ostr = fmt::sprintf("signalfd %s\n", strerror(errno));
    std::cerr << ostr;
    if (bDaemon) syslog(LOG_ERR, "%s", ostr.c_str());
    //exit(EXIT_FAILURE);
  }
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = sfd;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, sfd, &ev);


  itimer.it_interval.tv_nsec = 0;
  itimer.it_interval.tv_sec = 0;


  DnsQueryStatistics statistics(config->statisticsFile);

  for (;;) {
    int nfds = epoll_wait(epollfd, events, 100, -1);
    for (int _n = 0; _n < nfds; ++_n) {
      if ( udp_server_map.count(events[_n].data.fd)) {
        readIncomeQuery(events[_n].data.fd, buf, cliaddr, socklen, statistics);
      } else if (events[_n].data.fd == upserver_sock) {
        readServerResponse(upserver_sock,buf);
      } else if (events[_n].data.fd == localnet_server_sock) {
        readServerResponse(localnet_server_sock,buf);
      } else if (config->enableTcp and tcp_server_set.count(events[_n].data.fd)) {
        acceptTcpIncome(events[_n].data.fd, epollfd, cliaddr, socklen, ev);
      } else if (config->enableTcp and client_tcp_con.find(events[_n].data.fd) != client_tcp_con.end()) {
        readIncomeTcpQuery(epollfd, buf, events[_n], statistics);
      } else if (config->enableTcp and server_tcp_con.find(events[_n].data.fd) != server_tcp_con.end()) {
        HandleServerSideTcp(epollfd, buf, events[_n]);
      } else if (config->enableCache and events[_n].data.fd == cache_tfd) {
        DEBUG("cache time out")
        cache.timeout();

      } else if (events[_n].data.fd == tfd) {
        reqMessageTimeoutHandler();
      } else if (events[_n].data.fd == sfd) {
        // need to check which signal was sent
        bool exitFlag = signalHandler(sfd, statistics);
        if (exitFlag) {
          goto end;
        }

      }
    }
  }

  end:
  if (bDaemon) closelog();
  boost::checked_delete(config);
  close(epollfd);
  for (auto s : serverSockets) {
    close(s->socket);
    if (config->enableTcp) close(s->socket_tcp);
    boost::checked_delete(s);
  }
  close(upserver_sock);
  close(localnet_server_sock);
  std::cout << "EXIT_SUCCESS" << std::endl;
  return EXIT_SUCCESS;
}







