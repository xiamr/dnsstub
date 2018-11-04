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
#include <fnmatch.h>
#include <fstream>
#include <regex>
#include <functional>
#include <boost/algorithm/string.hpp>

using namespace std;

#ifdef NDEBUG
#define DEBUG(str)
#else
#define DEBUG(str) cout << str << endl;
#endif

const int max_udp_len = 65536;

bool bDaemon = false;
bool ipv6_first = false;
bool gfw_mode = false;
bool enable_tcp = false;
bool enable_cache = false;


string get_err_string(int num) {
  ostringstream os;
  os << "__LINE__ = " << num;
  return os.str();
}

class out_of_bound : public runtime_error {
public:
  explicit out_of_bound(int line);
};

class BadDnsError : public runtime_error {
public:
  explicit BadDnsError(const string &__arg) : runtime_error(__arg) {}

  explicit BadDnsError(const char *__arg) : runtime_error(__arg) {}

  BadDnsError() : runtime_error("BadDnsError") {}
};


out_of_bound::out_of_bound(int line) : runtime_error(get_err_string(line)) {}

class Cache;

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

  static unordered_map<enum QType, string> QType2Name;

  enum QClass : uint16_t {
    IN = 1, NOCLASS = 254, ALL = 255
  };

  static unordered_map<enum QClass, string> QClass2Name;

  class Question {
  public:
    string name;
    enum QType Type;
    enum QClass Class;

    bool operator==(const Question &q) const {
      return this->name == q.name and this->Type == q.Type and this->Class == q.Class;
    }
  };

  class Answer {
  public:
    string name;
    enum QType Type;
    enum QClass Class;
    unsigned int TTL;
    string rdata;

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

  vector<Question> questions;
  vector<Answer> answers;
  vector<Additional> additionals;


  string getName(char *&ptr, char *buf, const char *upbound);

  char *toName(string &name, char *ptr, const char *buf, const char *upbound,
               unordered_map<string, uint16_t> &str_map);

  unsigned short id{};
  unsigned short signs{};

  bool GFW_mode = true;

  bool use_localnet_dns_server = true;

  Dns *make_response_by_cache(Dns &dns, Cache &cache);

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


};

std::unordered_set<std::string> Dns::polluted_domains;

unordered_map<enum Dns::QType, string> Dns::QType2Name = {
    {A,     "A"},
    {NS,    "NS"},
    {CNAME, "CNAME"},
    {SOA,   "SOA"},
    {PTR,   "PTR"},
    {MX,    "MX"},
    {TXT,   "TXT"},
    {AAAA,  "AAAA"},
    {SRV,   "SRV"},
    {NAPTR, "NAPTR"},
    {OPT,   "OPT"},
    {IXPT,  "IXPT"},
    {AXFR,  "AXFR"},
    {ANY,   "ANY"}
};

unordered_map<enum Dns::QClass, string> Dns::QClass2Name = {
    {IN,      "IN"},
    {NOCLASS, "NOCLASS"},
    {ALL,     "ALL"}
};


void Dns::from_wire(char *buf, int len) {
  char *ptr = buf;
  const char *upbound = buf + len;
  unsigned short qdcout;
  unsigned short ancout;
  unsigned short nscout;
  unsigned short arcout;
  id = ntohs_ptr(ptr, upbound);
  signs = ntohs_ptr(ptr, upbound);
  qdcout = ntohs_ptr(ptr, upbound);
  ancout = ntohs_ptr(ptr, upbound);
  nscout = ntohs_ptr(ptr, upbound);
  arcout = ntohs_ptr(ptr, upbound);
  for (unsigned short i = 0; i < qdcout; i++) {
    Question question;
    question.name = getName(ptr, buf, upbound);
    question.Type = (QType) ntohs_ptr(ptr, upbound);
    question.Class = (QClass) ntohs_ptr(ptr, upbound);
    if (question.Type != QType::PTR and !isDomainValid(question.name))
      throw BadDnsError("domain name error : " + question.name);
    questions.push_back(question);
  }
  for (unsigned short i = 0; i < ancout; i++) {
    Answer answer;
    answer.name = getName(ptr, buf, upbound);
    answer.Type = (QType) ntohs_ptr(ptr, upbound);
    answer.Class = (QClass) ntohs_ptr(ptr, upbound);
    if (answer.Type != QType::PTR and !isDomainValid(answer.name))
      throw BadDnsError("domain name error : " + answer.name);
    answer.TTL = ntohl_ptr(ptr, upbound);
    uint16_t RDLENGTH = ntohs_ptr(ptr, upbound);
    if (ptr + RDLENGTH - 1 > upbound) throw out_of_bound(__LINE__);
    char mybuf[1024];
    switch (answer.Type) {
      case A:
        answer.rdata = inet_ntop(AF_INET, ptr, mybuf, 1024);
        ptr += RDLENGTH;
        break;
      case AAAA:
        answer.rdata = inet_ntop(AF_INET6, ptr, mybuf, 1024);
        ptr += RDLENGTH;
        break;
      default:
        answer.rdata = getName(ptr, buf, upbound);
        if (!isDomainValid(answer.rdata))
          throw BadDnsError("domain name error : " + answer.rdata);
    }

    answers.push_back(answer);
  }
  if (nscout) return;
  for (unsigned short i = 0; i < arcout; i++) {
    Additional additional;
    if (ptr > upbound) throw out_of_bound(__LINE__);
    additional.name = static_cast<uint8_t>(*ptr);
    ptr++;
    additional.Type = ntohs_ptr(ptr, upbound);
    additional.playload_size = ntohs_ptr(ptr, upbound);
    if (ptr > upbound) throw out_of_bound(__LINE__);
    additional.high_bit_in_extend_rcode = static_cast<uint8_t>(*ptr);
    ptr++;
    if (ptr > upbound) throw out_of_bound(__LINE__);
    additional.edns0_verion = static_cast<uint8_t>(*ptr);
    ptr++;
    additional.Z = ntohs_ptr(ptr, upbound);
    additional.data_length = ntohs_ptr(ptr, upbound);
    additionals.push_back(additional);
  }

  if (0 == (signs & QR) and !questions.empty()) {
    string domain = questions.front().name;
    for (const auto &pattern : Dns::polluted_domains) {
      if (fnmatch(pattern.c_str(), domain.c_str(), FNM_CASEFOLD) == 0) {
        // Match
        use_localnet_dns_server = false;
        break;
      }
    }
  }
}

char *Dns::toName(string &origin_name, char *ptr, const char *buf, const char *upbound,
                  unordered_map<string, uint16_t> &str_map) {
  string name = origin_name;
  name.erase(name.end() - 1);
  if (name.length() == 0) {
    *ptr = '\0';
    ptr++;
    return ptr;
  }
  char *now_ptr = ptr;
  uint8_t sublen = 0;
  size_t pos = 0;
  try {
    uint16_t off = str_map.at(name.substr(pos));
    if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
    *(uint16_t *) ptr = htons(off);
    *ptr |= 0xc0;
    ptr += 2;
    return ptr;
  } catch (out_of_range &) {
    str_map[name.substr(pos)] = ptr - buf;
  }
  ptr++;
  for (char &c : name) {
    if (c == '.') {
      if (sublen) {
        if (now_ptr > upbound) throw out_of_bound(__LINE__);
        *now_ptr = sublen;
      }
      sublen = 0;
      pos++;
      try {
        uint16_t off = str_map.at(name.substr(pos));
        if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
        *(uint16_t *) ptr = htons(off);
        *ptr |= 0xc0;
        ptr += 2;
        return ptr;
      } catch (out_of_range &) {
        str_map[name.substr(pos)] = ptr - buf;
      }
      now_ptr = ptr;
      ptr++;
    } else {
      if (ptr > upbound) throw out_of_bound(__LINE__);
      *ptr = c;
      sublen++;
      ptr++;
      pos++;
    }

  }
  if (sublen) {
    *now_ptr = sublen;
  }
  *ptr = '\0';
  ptr++;
  return ptr;

}

string Dns::getName(char *&ptr, char *buf, const char *upbound) {
  string name;
  bool first = true;
  while (true) {
    if (ptr > upbound) throw out_of_bound(__LINE__);
    unsigned char count = *ptr;

    char *locate;
    if (count & 0xc0) {
      // compressed label
      if (ptr + 1 > upbound) throw out_of_bound(__LINE__);
      locate = buf + 256 * (count & 0x3f) + *((uint8_t *) (ptr + 1));
      if (!first) name.append(1, '.');
      else first = false;
      name += getName(locate, buf, upbound);
      ptr += 2;
      break;
    } else {
      locate = ptr;
      ptr += count + 1;
    }
    if (count > 0) {
      if (locate + count > upbound) throw out_of_bound(__LINE__);
      if (!first) name.append(1, '.');
      else first = false;
      name.append(locate + 1, count);
    } else {
      name.append(1, '.');
      break;
    }
  }

  if (name.empty()) throw BadDnsError();
  return name;
}

void Dns::print() {
  cout << "id:" << id << endl;
  cout << "signs:" << signs << endl;
  cout << "qdcout:" << questions.size() << endl;
  cout << "ancout:" << answers.size() << endl;
  cout << "nscout:" << 0 << endl;
  cout << "arcout:" << 0 << endl;
  if (signs & QR) cout << "QR ";
  if (signs & AA) cout << "AA ";
  if (signs & TC) cout << "TC ";
  if (signs & RD) cout << "RD ";
  if (signs & RA) cout << "RA ";
  if (signs & AD) cout << "AD ";
  if (signs & CD) cout << "CD ";

  cout << "OpCode: " << get_opcode() << endl;
  cout << "RCode: " << get_rcode() << endl;

  cout << "Questions" << endl;
  for (auto &q : questions) {
    cout << q.name << "   " << QClass2Name[q.Class] << "  " << QType2Name[q.Type] << endl;
  }
  cout << "Answers" << endl;
  for (auto &ans : answers) {
    cout << ans.name << "  " << QClass2Name[ans.Class] << "   " << QType2Name[ans.Type] << "  " << ans.rdata
         << endl;
  }

}


ssize_t Dns::to_wire(char *buf, int n) {
  unordered_map<string, uint16_t> str_map;
  char *ptr = buf;
  const char *upbound = buf + n;
  htons_ptr(ptr, id, upbound);
  htons_ptr(ptr, signs, upbound);
  if (!(signs & QR) and GFW_mode and !use_localnet_dns_server) {
    htons_ptr(ptr, 2, upbound);
  } else {
    htons_ptr(ptr, questions.size(), upbound);
  }
  htons_ptr(ptr, answers.size(), upbound);
  htons_ptr(ptr, 0, upbound);
  htons_ptr(ptr, additionals.size(), upbound);
  if (!(signs & QR) and GFW_mode and !use_localnet_dns_server) {
    htons_ptr(ptr, 0xc012, upbound);
    htons_ptr(ptr, questions[0].Type, upbound);
    htons_ptr(ptr, questions[0].Class, upbound);
  }
  for (auto &q : questions) {
    ptr = toName(q.name, ptr, buf, upbound, str_map);
    htons_ptr(ptr, q.Type, upbound);
    htons_ptr(ptr, q.Class, upbound);
  }
  for (auto &ans : answers) {
    ptr = toName(ans.name, ptr, buf, upbound, str_map);
    htons_ptr(ptr, ans.Type, upbound);
    htons_ptr(ptr, ans.Class, upbound);
    htonl_ptr(ptr, ans.TTL, upbound);
    switch (ans.Type) {
      case A:
        htons_ptr(ptr, sizeof(in_addr), upbound);
        inet_pton(AF_INET, ans.rdata.c_str(), ptr);
        if (ptr + sizeof(struct in_addr) > upbound) throw out_of_bound(__LINE__);
        ptr += sizeof(struct in_addr);
        break;
      case AAAA:
        htons_ptr(ptr, sizeof(in6_addr), upbound);
        if (ptr + sizeof(struct in6_addr) > upbound) throw out_of_bound(__LINE__);
        inet_pton(AF_INET6, ans.rdata.c_str(), ptr);
        ptr += sizeof(struct in6_addr);
        break;
      default:
        char *len_ptr = ptr;
        ptr += 2;
        char *new_ptr = toName(ans.rdata, ptr, buf, upbound, str_map);
        if (len_ptr + 1 > upbound) throw out_of_bound(__LINE__);
        *(uint16_t *) len_ptr = htons(new_ptr - ptr);
        ptr = new_ptr;
    }
  }
  for (auto &add : additionals) {
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.name;
    ptr++;
    htons_ptr(ptr, add.Type, upbound);
    htons_ptr(ptr, add.playload_size, upbound);
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.high_bit_in_extend_rcode;
    ptr++;
    if (ptr > upbound) throw out_of_bound(__LINE__);
    *reinterpret_cast<uint8_t *>(ptr) = add.edns0_verion;
    ptr++;
    htons_ptr(ptr, add.Z, upbound);
    htons_ptr(ptr, add.data_length, upbound);
  }

  return ptr - buf;
}


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

void print_usage(char *argv[]) {
  cerr << "Usage: " << argv[0]
       << " [-d] [-u user] [-6] [-g] [-t] [-c] -l local_address -p local_port -b localnet_server_addresss -r remote_address"
       << endl;
  cerr << "-6 : ipv6 first" << endl;
  cerr << "-d : daemon mode" << endl;
  cerr << "-g : great firewall mode" << endl;
  cerr << "-t : enable tcp support" << endl;
  cerr << "-c : enable internal cache" << endl;
}


class Cache {
public:
  class Item;

  class Relation {
  public:
    Dns::QType type;
    Item *parent_item;
    Item *child_item;
    double exp_time;
    int i;
  };

  enum ItemType {
    A, AAAA, DOMAIN
  };

  class Item {
  public:
    string name;
    unordered_set<Relation *> parent_relations;
    unordered_set<Relation *> child_relations;
  };

  void construct(Dns &dns) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    double mtime = time.tv_sec + time.tv_nsec * 10e-9;
    for (auto &ans : dns.answers) {
      auto it1 = item_hash.find(ans.name);
      Item *p1, *p2;
      if (it1 == item_hash.end()) {
        p1 = new Item();
        p1->name = ans.name;
        item_hash[p1->name] = p1;
      } else {
        p1 = it1->second;
      }

      auto it2 = item_hash.find(ans.rdata);
      if (it2 == item_hash.end()) {
        p2 = new Item();
        p2->name = ans.rdata;
        item_hash[p2->name] = p2;
      } else {
        p2 = it2->second;
      }

      Relation *relation = nullptr;
      for (auto &r : p1->child_relations) {
        if (r->type == ans.Type) {
          if (r->child_item == p2)
            relation = r;
        }
      }
      bool exist = true;

      if (!relation) {
        exist = false;
        relation = new Relation();
        relation->type = ans.Type;
      }
      relation->parent_item = p1;
      relation->child_item = p2;

      p1->child_relations.insert(relation);
      p2->parent_relations.insert(relation);
      double old = relation->exp_time;
      relation->exp_time = ans.TTL + mtime;
      if (!exist) min_heap_insert(relation);
      else {
        if (relation->exp_time > old) heap_increase_key(relation->i);
        else if (relation->exp_time < old) heap_decrease_key(relation->i);
      }
    }
    set_timer(mtime);
  }

  Item *getItem(const string &name) {
    auto it = item_hash.find(name);
    if (it == item_hash.end()) return nullptr;
    else return it->second;
  }

  void timeout() {
    // timeout event from epoll
    // remove some relations
    // if no relation link item, remove also
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    double mtime = time.tv_sec + time.tv_nsec * 10e-9;

    for (;;) {
      Relation *r = heap_min();
      if (r and r->exp_time < mtime + 1) {
        r->parent_item->child_relations.erase(r);
        r->child_item->parent_relations.erase(r);

        delete heap_extraxt_min();
        if ((r->parent_item->parent_relations.size() + r->parent_item->child_relations.size()) == 0) {
          item_hash.erase(r->parent_item->name);
          delete r->parent_item;
        }
        if ((r->child_item->parent_relations.size() + r->child_item->child_relations.size()) == 0) {
          item_hash.erase(r->child_item->name);
          delete r->child_item;
        }

        continue;
      }
      break;
    }
    ///
    set_timer(mtime);

  }

  void set_timer_fd(int timer_fd) {
    this->timer_fd = timer_fd;
  }

  unordered_set<string> noipv6_domain;
private:
  unordered_map<string, Item *> item_hash;

  vector<Relation *> sorted_heap;
  int timer_fd;
  double last_timer = 0.0;

  void set_timer(double mtime) {
    struct itimerspec itimer;
    itimer.it_interval.tv_nsec = 0;
    itimer.it_interval.tv_sec = 0;

    if (sorted_heap.empty()) {
      itimer.it_value.tv_sec = 0;
    } else {
      itimer.it_value.tv_sec = heap_min()->exp_time;
    }
    itimer.it_value.tv_nsec = 0;
    double ntime = itimer.it_value.tv_sec + itimer.it_value.tv_nsec * 10e-9;
    if (abs(static_cast<int>(ntime - last_timer)) < 1)
      return;
    timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &itimer, nullptr);
    last_timer = ntime;

  }

  void min_heap_insert(Relation *key) {
    sorted_heap.push_back(key);
    key->i = sorted_heap.size() - 1;
    heap_decrease_key(key->i);
  }

  int PARENT(int i) { return (i + 1) / 2 - 1; }

  int LEFT_CHILD(int i) { return 2 * (i + 1) - 1; }

  int RIGHT_CHILD(int i) { return 2 * (i + 1); }

  void heap_decrease_key(int i) {
    while (i > 0 and sorted_heap[PARENT(i)]->exp_time > sorted_heap[i]->exp_time) {
      swap(i, PARENT(i));
      i = PARENT(i);
    }
  }

  void heap_increase_key(int i) {
    // left 2*(i+1) - 1  and right 2*(i+1)

    unsigned long size = sorted_heap.size();
    for (;;) {

      int left_child = LEFT_CHILD(i);
      int right_child = RIGHT_CHILD(i);

      if (left_child < size and right_child < size) {
        if (sorted_heap[left_child]->exp_time < sorted_heap[right_child]->exp_time) {
          swap(i, left_child);
          i = left_child;
        } else {
          swap(i, right_child);
          i = right_child;
        }
      } else if (left_child < size) {
        swap(i, left_child);
        i = left_child;
      } else if (right_child < size) {
        swap(i, right_child);
        i = right_child;
      } else {
        break;
      }
    }
  }

  void swap(int i, int j) {
    Relation *tmp = sorted_heap[j];
    sorted_heap[j] = sorted_heap[i];
    sorted_heap[i] = tmp;

    sorted_heap[i]->i = i;
    sorted_heap[j]->i = j;

  }


  Relation *heap_min() {
    if (sorted_heap.empty()) return nullptr;
    return sorted_heap[0];
  }

  Relation *heap_extraxt_min() {
    if (sorted_heap.empty()) return nullptr;
    Relation *r = sorted_heap[0];
    sorted_heap[0] = sorted_heap[sorted_heap.size() - 1];
    sorted_heap[0]->i = 0;
    sorted_heap.pop_back();
    heap_increase_key(0);
    return r;
  }


};

bool c_timeout = false;

bool deep_find(Cache::Item *p, vector<Dns::Answer> &res_anss,
               Cache &cache, Dns::QType type, struct timespec &time) {
  bool found = false;
  for (auto &r : p->child_relations) {
    if (r->type == type) {
      Dns::Answer ans;
      ans.name = p->name;
      ans.Type = r->type;
      ans.rdata = r->child_item->name;
      ans.Class = Dns::IN;
      long ttl = r->exp_time - time.tv_sec;
      if (ttl < 1) {
        c_timeout = true;
        continue;
      } else ans.TTL = ttl;
      found = true;
      res_anss.insert(res_anss.begin(), ans);
    } else if (r->type == Dns::CNAME) {
      if (deep_find(r->child_item, res_anss, cache, type, time)) {
        Dns::Answer ans;
        ans.name = p->name;
        ans.Type = r->type;
        ans.rdata = r->child_item->name;
        ans.Class = Dns::IN;
        long ttl = r->exp_time - time.tv_sec;
        if (ttl < 1) {
          c_timeout = true;
          continue;
        } else ans.TTL = ttl;
        found = true;
        res_anss.insert(res_anss.begin(), ans);
      }
    }
  }
  return found;
}

Dns *Dns::make_response_by_cache(Dns &dns, Cache &cache) {
  vector<Answer> res_anss;
  auto &q = dns.questions[0];
  Cache::Item *p = cache.getItem(q.name);
  if (p == nullptr) return nullptr;
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  c_timeout = false;

  if (deep_find(p, res_anss, cache, q.Type, time)) {
    Dns *dns2 = new Dns();
    dns2->id = dns.id;
    dns2->signs = dns.signs;
    dns2->signs |= Dns::RA | Dns::QR;
    dns2->questions = dns.questions;
    dns2->answers = res_anss;
    return dns2;
  }
  if (c_timeout) {
    cache.timeout();
  }

  return nullptr;
}

// read the config file that contains the polluted domains
void Dns::load_polluted_domains(const std::string &config_filename) {
  polluted_domains.clear();
  std::ifstream fs;
  fs.open(config_filename);
  if (fs) {
    string line;
    while (!fs.eof()) {
      std::getline(fs, line);
      boost::trim(line);
      if (!line.empty()) {
        if ('#' == line[0]) continue;
        if ('!' == line[0]) continue;
        polluted_domains.insert(line);
      }
    }
    fs.close();
    return;
  }
  cerr << "config file (" << config_filename << ") was not opened !" << endl;
}

bool Dns::isDomainValid(const std::string &domain) {
  static auto validDomainPattern = std::regex(
      "^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\\.$|\\.)");
  return std::regex_match(domain, validDomainPattern);
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

  ~Upstream() {
    delete[] buf;
  }
};

unordered_map<uint16_t, Upstream *> id_map;
Upstream *oldest_up = nullptr, *newest_up = nullptr;

struct itimerspec itimer;

int tfd;

unordered_map<int, Upstream *> client_tcp_con;
unordered_map<int, Upstream *> server_tcp_con;
struct sockaddr_storage upserver_addr;
struct sockaddr_storage localnet_server_addr;


int upserver_sock;
int localnet_server_sock;
Cache cache;
long last_timer = 0;

class DnsQueryStatistics {
  struct KeyHasher {
    std::size_t operator()(const Dns::Question& t) const {
      return ((std::hash<std::string>()(t.name)
          ^(hash<uint16_t>()(t.Class) << 1)) >> 1)
          ^(hash<uint16_t>()(t.Type) << 1);
    }
  };

  std::unordered_map<Dns::Question, long, KeyHasher> _statistics;
  std::string statisticsFileName;
public:
  explicit DnsQueryStatistics(const std::string &statisticsFileName) :
  statisticsFileName(statisticsFileName),
  _statistics(){
  }

  void countNewQuery(const Dns &dns) {
    auto iterator = _statistics.find(dns.questions.front());
    if (iterator != _statistics.end()) {
      (*iterator).second++;
    } else {
      _statistics[dns.questions.front()] = 1;
    }
  }

  void printStatisticsInfos() {
    std::ostream *os = nullptr;
    if (statisticsFileName.empty()) {
      os = &(std::cout);
    } else {
      auto ofs = new std::ofstream();
      os = ofs;
      ofs->open(statisticsFileName);
      if (ofs->fail()) {
        std::cerr << "error opening statisticsInfo file <" << statisticsFileName << "> !" << std::endl;
        delete ofs;
        return;
      }
    }
    *os << "------------ statistics ------------------------" << endl;

    *os << "Count\tClass\tType\t\tName" << std::endl;
    for (auto &item : _statistics) {
      auto &q = item.first;
      *os << item.second << "\t\t" << Dns::QClass2Name[q.Class] << "\t\t" << Dns::QType2Name[q.Type]
          << "\t\t" << q.name << endl;
    }
    *os << "------------------------------------------------" << endl;
    if (typeid(*os) == typeid(std::ofstream)){
      delete os;
    }
  }
};

bool add_upstream(char *buf, ssize_t n, Upstream *upstream) {
  if (upstream->dns1.questions.empty()) {
    delete upstream;
    return false;
  }
  auto &q = upstream->dns1.questions[0];
  ostringstream os;
  os << q.name << "  " << Dns::QClass2Name[q.Class] << "    "
     << Dns::QType2Name[q.Type] << endl;

  cout << os.str();
  if (bDaemon) syslog(LOG_INFO, "%s", os.str().c_str());

  if (q.Type == Dns::A and ipv6_first) {
    q.Type = Dns::AAAA;
    upstream->checked_ipv6 = false;
  } else {
    upstream->checked_ipv6 = true;
  }
  upstream->dns1.GFW_mode = gfw_mode;

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
      delete upstream;
      return nullptr;
    } catch (BadDnsError) {
      delete upstream;
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
          cerr << "Memory Access Error : " << err.what() << endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          delete upstream;
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
          cerr << "Memory Access Error : " << err.what() << endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          delete upstream;
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
              cerr << "send error : " << __LINE__ << strerror(errno) << endl;
              if (bDaemon)
                syslog(LOG_WARNING, "sendto up stream error %d : %s", __LINE__, strerror(errno));
            }
          } else if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr, sizeof(upserver_addr)) <
                     0) {
            cerr << "send error : " << __LINE__ << strerror(errno) << endl;
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
          cerr << "Memory Access Error : " << err.what() << endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
          delete upstream;
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

void readLocalServerResponse(int server_sock, char *buf) {
  ssize_t n;
  while ((n = recv(localnet_server_sock, buf, max_udp_len, 0)) > 0) {
    DEBUG("recv udp response from localnet dns server")
    auto upstream = check(buf, n, false);
    if (upstream == nullptr) continue;

    *(uint16_t *) buf = htons(upstream->cli_id);
    DEBUG("send udp response to client")
    sendto(server_sock, buf, n, 0, (sockaddr *) &upstream->cliaddr, upstream->socklen);
    id_map.erase(upstream->up_id);
    delete upstream;
    upstream = nullptr;
  }
}

void readRemoteServerResponse(int server_sock, char *buf) {
  ssize_t n;
  while ((n = recv(upserver_sock, buf, max_udp_len, 0)) > 0) {
    DEBUG("recv udp response from server")
    auto upstream = check(buf, n, false);
    if (upstream == nullptr) continue;

    *(uint16_t *) buf = htons(upstream->cli_id);
    DEBUG("send udp response to client")
    sendto(server_sock, buf, n, 0, (sockaddr *) &upstream->cliaddr, upstream->socklen);
    id_map.erase(upstream->up_id);
    delete upstream;
    upstream = nullptr;
  }
}

void
readIncomeQuery(int server_sock, char *buf, sockaddr_storage &cliaddr, socklen_t &socklen,
    DnsQueryStatistics &statistics) {
  ssize_t n;
  while ((n = recvfrom(server_sock, buf, 65536, 0, (sockaddr *) &cliaddr, &socklen)) > 0) {
    DEBUG("new udp request from client")

    auto up = new Upstream;
    try {
      up->dns1.from_wire(buf, n);
    } catch (out_of_bound &err) {
      cerr << "Memory Access Error : " << err.what() << endl;
      if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
    } catch (BadDnsError) {
      cerr << "Bad Dns " << endl;
    }
    if (up->dns1.questions.empty()) {
      delete up;
      continue;
    }
    statistics.countNewQuery(up->dns1);
    Dns *response = nullptr;
    if (ipv6_first) {
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
        cerr << "Memory Access Error : " << err.what() << endl;
        if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
      }
      DEBUG("send response to client from cache")
      sendto(server_sock, buf, n, 0, (sockaddr *) &cliaddr, socklen);
      delete response;
      delete up;
    } else {
      memcpy(&up->cliaddr, &cliaddr, socklen);
      up->socklen = socklen;
      if (!add_upstream(buf, n, up)) continue;
      if (ipv6_first or gfw_mode) {
        try {
          n = up->dns1.to_wire(buf, max_udp_len);
        } catch (out_of_bound &err) {
          cerr << "Memory Access Error : " << err.what() << endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
          delete up;
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
          cerr << "send error : " << __LINE__ << endl;
          if (bDaemon) syslog(LOG_WARNING, "sendto up stream error ");
        }
      } else if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr,
                        sizeof(upserver_addr)) < 0) {
        cerr << "send error  : " << __LINE__ << endl;
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
        cerr << "Memory Access Error : " << err.what() << endl;
        if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
      } catch (BadDnsError) {
        cerr << "Bad Dns " << endl;
      }
      if (up->dns1.questions.empty()) {
        delete up;
        close(up->cli_fd);
        client_tcp_con.erase(up->cli_fd);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
        return;
      }
      statistics.countNewQuery(up->dns1);
      Dns *response = nullptr;
      if (ipv6_first) {
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
          cerr << "Memory Access Error : " << err.what() << endl;
          if (bDaemon) syslog(LOG_ERR, "Memory Access Error : %s", err.what());
        }
        *(uint16_t *) buf = htons(n);
        DEBUG("send tcp response to client from cache")
        write(up->cli_fd, buf, n + 2);
        close(up->cli_fd);
        client_tcp_con.erase(up->cli_fd);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
        delete up;
        delete response;

      } else {
        if (!add_upstream(up->buf, up->buf_len, up)) return;
        int upfd = socket(upserver_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        if (upfd < 0) {
          perror("Can not open socket ");
          if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
        }
        struct epoll_event ev;
        ev.events = EPOLLET | EPOLLOUT | EPOLLERR;
        ev.data.fd = upfd;
        epoll_ctl(epollfd, EPOLL_CTL_ADD, upfd, &ev);
        DEBUG("new tcp connnect to server")
        int ret = connect(upfd, (sockaddr *) &upserver_addr, sizeof(upserver_addr));
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
    delete up;
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
    delete[] up->buf;
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
      delete upstream;
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
    delete up;
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
      cerr << "signalfd read error " << endl;
      return false;
    }
    switch (signalfdSiginfo.ssi_signo) {
      case SIGUSR1:
        cout << "reloading config file <pollution_domains.config> ..." << endl;
        Dns::load_polluted_domains("pollution_domains.config");
        cout << "reload complete !" << endl;
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
        cerr << "unexcepted signal (" << signalfdSiginfo.ssi_signo << ") " << endl;
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
      delete up;
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


void parseArguments(int argc, char *argv[], char *&localnet_server_address, char *&local_address, uint16_t &local_port,
                    char *&remote_address, char *&new_user, char *&statisticsFile) {
  int opt;
  while ((opt = getopt(argc, argv, "6cgtu:dl:p:r:b:s:")) != -1) {
    switch (opt) {
      case '6':
        ipv6_first = true;
        break;
      case 'g':
        gfw_mode = true;
        break;
      case 'b':
        localnet_server_address = optarg;
        break;
      case 'l':
        local_address = optarg;
        break;
      case 'p': {
        long port = strtol(optarg, nullptr, 10);
        if (port < 1 or port > 65535) {
          cerr << "port range error : " << port << endl;
          print_usage(argv);
          exit(EXIT_FAILURE);
        }
        local_port = port;
      }
        break;
      case 'r':
        remote_address = optarg;
        break;
      case 'd':
        bDaemon = true;
        break;
      case 'u':
        new_user = optarg;
        break;
      case 't':
        enable_tcp = true;
        break;
      case 'c':
        enable_cache = true;
        break;
      case 's':
        statisticsFile = optarg;
        break;
      default:
        print_usage(argv);
        exit(EXIT_FAILURE);
    }
  }

  if (local_address == nullptr or remote_address == nullptr or local_port == 0) {
    print_usage(argv);
    exit(EXIT_FAILURE);
  }

}


int main(int argc, char *argv[]) {

  char *new_user = nullptr;
  char *local_address = nullptr;
  uint16_t local_port = 0;
  char *remote_address = nullptr;
  char *localnet_server_address = nullptr;
  char *statisticsFile = nullptr;

  parseArguments(argc, argv, localnet_server_address, local_address, local_port, remote_address, new_user,
                 statisticsFile );

  Dns::load_polluted_domains("pollution_domains.config");

  std::cout << "Start Server ..." << std::endl;
  if (bDaemon) {
    cout << "Enter daemon mode .." << endl;
    cout << "Open syslog facility .. " << endl;
    daemon(0, 0);
    openlog(argv[0], LOG_PID, LOG_USER);
  }

  struct sockaddr_storage server_addr;
  bzero(&server_addr, sizeof(server_addr));

  if (inet_pton(AF_INET6, local_address, &((sockaddr_in *) &server_addr)->sin_addr)) {
    server_addr.ss_family = AF_INET6;
    ((sockaddr_in6 *) &server_addr)->sin6_port = htons(local_port);
  } else if (inet_pton(AF_INET, local_address, &((sockaddr_in *) &server_addr)->sin_addr)) {
    server_addr.ss_family = AF_INET;
    ((sockaddr_in *) &server_addr)->sin_port = htons(local_port);
  } else {
    cerr << "Local addresss is invaild" << endl;
    if (bDaemon) syslog(LOG_ERR, "Local addresss(%s) is invaild", local_address);
    exit(EXIT_FAILURE);
  }
  int server_sock = socket(server_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  if (server_sock < 0) {
    perror("Can not open socket ");
    if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
    exit(EXIT_FAILURE);
  }
  if (bind(server_sock, (sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
    perror("bind failed !");
    if (bDaemon) syslog(LOG_ERR, "Can not bind port(%d) for listening", local_port);
    exit(EXIT_FAILURE);
  }
  int server_sock_tcp = 0;
  if (enable_tcp) {
    server_sock_tcp = socket(server_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (server_sock_tcp < 0) {
      perror("Can not open socket ");
      if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
      exit(EXIT_FAILURE);
    }
    if (bind(server_sock_tcp, (sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
      perror("bind failed !");
      if (bDaemon) syslog(LOG_ERR, "Can not bind port(%d) for listening", local_port);
      exit(EXIT_FAILURE);
    }
    if (listen(server_sock_tcp, 10) < 0) {
      perror("listen failed !");

      exit(EXIT_FAILURE);
    }
  }

  bzero(&upserver_addr, sizeof(upserver_addr));

  if (inet_pton(AF_INET6, remote_address, &((sockaddr_in6 *) &upserver_addr)->sin6_addr)) {
    upserver_addr.ss_family = AF_INET6;
    ((sockaddr_in6 *) &upserver_addr)->sin6_port = htons(53);
  } else if (inet_pton(AF_INET, remote_address, &((sockaddr_in *) &upserver_addr)->sin_addr)) {
    upserver_addr.ss_family = AF_INET;
    ((sockaddr_in *) &upserver_addr)->sin_port = htons(53);
  } else {
    cerr << "Remote addresss is invaild" << endl;
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

  if (inet_pton(AF_INET, localnet_server_address, &((sockaddr_in *) &localnet_server_addr)->sin_addr)) {
    localnet_server_addr.ss_family = AF_INET;
    ((sockaddr_in *) &localnet_server_addr)->sin_port = htons(53);
  } else {
    cerr << "local net dns server address resolve error" << endl;
    exit(EXIT_FAILURE);
  }

  localnet_server_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

  if (localnet_server_sock < 0) {
    perror("Can not open socket for localnet dns server");
    exit(EXIT_FAILURE);
  }

  if (new_user) {
    struct passwd *pass = getpwnam(new_user);
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
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = server_sock;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, server_sock, &ev);

  if (enable_tcp) {
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_sock_tcp;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, server_sock_tcp, &ev);
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
  if (enable_cache) {
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
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    ostringstream os;
    os << "sigprocmask" << strerror(errno) << endl;
    cerr << os.str();
    if (bDaemon) syslog(LOG_ERR, "%s", os.str().c_str());
    //exit(EXIT_FAILURE);
  }
  int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
  if (sfd == -1) {
    ostringstream os;
    os << "signalfd" << strerror(errno) << endl;
    cerr << os.str();
    if (bDaemon) syslog(LOG_ERR, "%s", os.str().c_str());
    //exit(EXIT_FAILURE);
  }
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = sfd;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, sfd, &ev);


  itimer.it_interval.tv_nsec = 0;
  itimer.it_interval.tv_sec = 0;



  DnsQueryStatistics statistics(statisticsFile ? statisticsFile : "");

  for (;;) {
    int nfds = epoll_wait(epollfd, events, 100, -1);
    for (int _n = 0; _n < nfds; ++_n) {
      if (events[_n].data.fd == server_sock) {
        readIncomeQuery(server_sock, buf, cliaddr, socklen, statistics);
      } else if (events[_n].data.fd == upserver_sock) {
        readRemoteServerResponse(server_sock, buf);
      } else if (events[_n].data.fd == localnet_server_sock) {
        readLocalServerResponse(server_sock, buf);
      } else if (enable_tcp and events[_n].data.fd == server_sock_tcp) {
        acceptTcpIncome(server_sock_tcp, epollfd, cliaddr, socklen, ev);
      } else if (enable_tcp and client_tcp_con.find(events[_n].data.fd) != client_tcp_con.end()) {
        readIncomeTcpQuery(epollfd, buf, events[_n], statistics);
      } else if (enable_tcp and server_tcp_con.find(events[_n].data.fd) != server_tcp_con.end()) {
        HandleServerSideTcp(epollfd, buf, events[_n]);
      } else if (enable_cache and events[_n].data.fd == cache_tfd) {
        DEBUG("cache time out")
        cache.timeout();

      } else if (events[_n].data.fd == tfd) {
        reqMessageTimeoutHandler();
      } else if (events[_n].data.fd == sfd) {
        // need to check which signal was sent
        bool exitFlag = signalHandler(sfd, statistics);
        if (exitFlag){
          goto end;
        }

      }
    }
  }

  end:
  if (bDaemon) closelog();

  close(epollfd);
  close(server_sock);
  close(upserver_sock);
  std::cout << "EXIT_SUCCESS" << std::endl;
  return EXIT_SUCCESS;
}





