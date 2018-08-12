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

using namespace std;

const int max_udp_len = 65536;

bool bDaemon = false;
bool ipv6_first = false;
bool gfw_mode = false;
bool enable_tcp = false;


string get_err_string(int num) {
    ostringstream os;
    os << "__LINE__ = " << num;
    return os.str();
}

class out_of_bound : public runtime_error {
public:
    explicit out_of_bound(int line);
};

out_of_bound::out_of_bound(int line) : runtime_error(get_err_string(line)) {}


class dns {
public:
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

    dns(char buf[], int len) {
        from_wire(buf, len);
    }

    dns() = default;

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

unordered_map<enum dns::QType, string> dns::QType2Name = {
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

unordered_map<enum dns::QClass, string> dns::QClass2Name = {
        {IN,      "IN"},
        {NOCLASS, "NOCLASS"},
        {ALL,     "ALL"}
};


void dns::from_wire(char *buf, int len) {
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
        questions.push_back(question);
    }
    for (unsigned short i = 0; i < ancout; i++) {
        Answer answer;
        answer.name = getName(ptr, buf, upbound);
        answer.Type = (QType) ntohs_ptr(ptr, upbound);
        answer.Class = (QClass) ntohs_ptr(ptr, upbound);
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
}

char *dns::toName(string &name, char *ptr, const char *buf, const char *upbound,
                  unordered_map<string, uint16_t> &str_map) {
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

string dns::getName(char *&ptr, char *buf, const char *upbound) {
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
            if (!first) name.append(1, '.');
            else first = false;
            if (locate + count > upbound) throw out_of_bound(__LINE__);
            name.append(locate + 1, count);
        } else {
            break;
        }
    }
    return name;
}

void dns::print() {
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


ssize_t dns::to_wire(char *buf, int n) {
    unordered_map<string, uint16_t> str_map;
    char *ptr = buf;
    const char *upbound = buf + n;
    htons_ptr(ptr, id, upbound);
    htons_ptr(ptr, signs, upbound);
    if (!(signs & QR) and GFW_mode) {
        htons_ptr(ptr, 2, upbound);
    } else {
        htons_ptr(ptr, questions.size(), upbound);
    }
    htons_ptr(ptr, answers.size(), upbound);
    htons_ptr(ptr, 0, upbound);
    htons_ptr(ptr, additionals.size(), upbound);
    if (!(signs & QR) and GFW_mode) {
        htons_ptr(ptr, 0xc012, upbound);
        htons_ptr(ptr, questions[0].Type, upbound);
        htons_ptr(ptr, questions[0].Class, upbound);
    }
    for (auto &q : questions) {
        char *new_ptr = toName(q.name, ptr, buf, upbound, str_map);
        ptr = new_ptr;
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
    cerr << "Usage: " << argv[0] << " [-d] [-u user] [-6] [-g] [-t] -l local_address -p local_port -r remote_address"
         << endl;
    cerr << "-6 : ipv6 first" << endl;
    cerr << "-d : daemon mode" << endl;
    cerr << "-g : great firewall mode" << endl;
    cerr << "-t : enable tcp support" << endl;
}

class Upstream {
public:
    uint16_t cli_id;
    sockaddr_storage cliaddr;
    socklen_t socklen;
    bool checked_ipv6;
    bool ipv6_trun = false;
    dns dns1;
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
        if (buf) delete[] buf;
    }
};

unordered_map<uint16_t, Upstream *> id_map;
Upstream *oldest_up = nullptr, *newest_up = nullptr;

struct itimerspec itimer;

int tfd;

unordered_map<int, Upstream *> client_tcp_con;
unordered_map<int, Upstream *> server_tcp_con;
struct sockaddr_storage upserver_addr;
int upserver_sock;


bool add_upstream(char *buf, ssize_t n, Upstream *upstream) {
    try {
        upstream->dns1.from_wire(buf, n);
    } catch (out_of_bound &err) {
        cerr << "Memory Access Error : " << err.what() << endl;
        if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
        delete upstream;
        return false;
    }

    if (upstream->dns1.questions.empty()) {
        delete upstream;
        return false;
    }
    auto &q = upstream->dns1.questions[0];
    ostringstream os;
    os << q.name << "  " << dns::QClass2Name[q.Class] << "    "
       << dns::QType2Name[q.Type] << endl;
    cout << os.str();
    if (bDaemon) syslog(LOG_INFO, "%s", os.str().c_str());

    if (q.Type == dns::A and ipv6_first) {
        q.Type = dns::AAAA;
        upstream->checked_ipv6 = false;
    } else {
        upstream->checked_ipv6 = true;
    }
    upstream->dns1.GFW_mode = gfw_mode;

    upstream->cli_id = upstream->dns1.id;
    upstream->dns1.id = get_id();
    upstream->up_id = upstream->dns1.id;


    clock_gettime(CLOCK_MONOTONIC_COARSE, &upstream->time);
    upstream->next = nullptr;
    upstream->prev = newest_up;
    newest_up = upstream;
    if (!oldest_up) {
        oldest_up = upstream;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &itimer.it_value);
        itimer.it_value.tv_sec += 60; // 60 secs
        timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
    } else {
        upstream->prev->next = upstream;
    }
    id_map[upstream->up_id] = upstream;
    return true;
}

Upstream *check(char *buf, ssize_t &n, sockaddr *upserver_addr, socklen_t socklen, bool tcp) {
    uint16_t up_id = ntohs(*(uint16_t *) buf);
    auto it = id_map.find(up_id);
    if (it != id_map.end()) {
        Upstream *upstream = it->second;
        if (!upstream->prev and upstream->next) {
            oldest_up = upstream->next;
            oldest_up->prev = nullptr;
            itimer.it_value.tv_sec = oldest_up->time.tv_sec + 60; // 60 secs
            itimer.it_value.tv_nsec = oldest_up->time.tv_nsec;
            timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, NULL);
        } else if (!upstream->prev and !upstream->next) {
            oldest_up = newest_up = nullptr;
            itimer.it_value.tv_sec = 0;
            itimer.it_value.tv_nsec = 0;
            timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, NULL);
        } else if (upstream->prev and !upstream->next) {
            newest_up = upstream->prev;
            newest_up->next = nullptr;
        } else {
            upstream->prev->next = upstream->next;
            upstream->next->prev = upstream->prev;
        }

        if (!upstream->checked_ipv6) {
            dns dns1;
            try {
                dns1.from_wire(buf, n);
            } catch (out_of_bound &err) {
                delete upstream;
                return nullptr;
            }
            for (auto &ans : dns1.answers) {
                if (ans.Type == dns::AAAA) {
                    upstream->checked_ipv6 = true;
                    break;
                }
            }
            if (!upstream->checked_ipv6 and dns1.signs & dns::TC) upstream->ipv6_trun = true;

            if (upstream->checked_ipv6) {
                dns1.questions[0].Type = dns::A;

                try {
                    n = dns1.to_wire(buf, max_udp_len);
                } catch (out_of_bound &err) {
                    cerr << "Memory Access Error : " << err.what() << endl;
                    if (bDaemon) syslog(LOG_ERR, "Memory Access Error %d : %s", __LINE__, err.what());
                    delete upstream;
                    return nullptr;
                }
            } else {
                upstream->checked_ipv6 = true;
                upstream->dns1.questions[0].Type = dns::A;
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

                    int upfd = socket(upserver_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
                    if (upfd < 0) {
                        perror("Can not open socket ");
                        if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
                        exit(EXIT_FAILURE);
                    }
                    setnonblocking(upfd);
                    struct epoll_event ev;
                    ev.events = EPOLLET | EPOLLOUT | EPOLLRDHUP;
                    ev.data.fd = upfd;
                    int ret = connect(upfd, (sockaddr *) upserver_addr, socklen);
                    if (ret < 0 and errno != EINPROGRESS) {
                        if (bDaemon) syslog(LOG_ERR, "connect failed %d : %s ", __LINE__, strerror(errno));
                        return nullptr;
                    }
                    upstream->ser_fd = upfd;
                    server_tcp_con[upfd] = upstream;
                } else {
                    if (sendto(upserver_sock, buf, n, 0, (sockaddr *) upserver_addr, socklen) < 0) {
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
                newest_up = upstream;
                if (!oldest_up) {
                    oldest_up = upstream;
                    clock_gettime(CLOCK_MONOTONIC_COARSE, &itimer.it_value);
                    itimer.it_value.tv_sec += 60; // 60 secs
                    timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
                } else {
                    upstream->prev->next = upstream;
                }
                clock_gettime(CLOCK_MONOTONIC_COARSE, &upstream->time);
                id_map[upstream->dns1.id] = upstream;
                return nullptr;

            }
        } else {

            if (upstream->ipv6_trun) {
                dns dns1;
                try {
                    dns1.from_wire(buf, n);
                } catch (out_of_bound &err) {
                    delete upstream;
                    return nullptr;
                }
                dns1.answers.clear();
                dns1.signs |= dns::TC;
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
    int n = 0;
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


int main(int argc, char *argv[]) {

    char *new_user = nullptr;
    char *local_address = nullptr;
    uint16_t local_port = 0;
    char *remote_address = nullptr;

    int opt;
    while ((opt = getopt(argc, argv, "6gtu:dl:p:r:")) != -1) {
        switch (opt) {
            case '6':
                ipv6_first = true;
                break;
            case 'g':
                gfw_mode = true;
                break;
            case 'l':
                local_address = optarg;
                break;
            case 'p': {
                long port = strtol(optarg, NULL, 10);
                local_port = port;
                if (local_port != port) {
                    cerr << "port range error : " << port << endl;
                    print_usage(argv);
                    exit(EXIT_FAILURE);
                }
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
            default:
                print_usage(argv);
                exit(EXIT_FAILURE);
        }
    }

    if (local_address == nullptr or remote_address == nullptr or local_port == 0) {
        print_usage(argv);
        exit(EXIT_FAILURE);
    }

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
    int server_sock = socket(server_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    setnonblocking(server_sock);
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
        server_sock_tcp = socket(server_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
        setnonblocking(server_sock_tcp);
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
    upserver_sock = socket(upserver_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (upserver_sock < 0) {
        perror("Can not open socket ");
        if (bDaemon) syslog(LOG_ERR, "Can not open socket remote up stream server communication");
        exit(EXIT_FAILURE);
    }
    setnonblocking(upserver_sock);

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

    struct epoll_event ev, events[10];
    int epollfd;
    epollfd = epoll_create(10);
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

    tfd = timerfd_create(CLOCK_MONOTONIC_COARSE, 0);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = tfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, tfd, &ev);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        ostringstream os;
        os << "sigprocmask" << strerror(errno) << endl;
        cerr << os.str();
        if (bDaemon) syslog(LOG_ERR, "%s", os.str().c_str());
        exit(EXIT_FAILURE);
    }
    int sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
        ostringstream os;
        os << "signalfd" << strerror(errno) << endl;
        cerr << os.str();
        if (bDaemon) syslog(LOG_ERR, "%s", os.str().c_str());
        exit(EXIT_FAILURE);
    }
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, sfd, &ev);


    itimer.it_interval.tv_nsec = 0;
    itimer.it_interval.tv_sec = 0;


    for (;;) {
        int nfds = epoll_wait(epollfd, events, 10, -1);
        for (int _n = 0; _n < nfds; ++_n) {
            if (events[_n].data.fd == server_sock) {
                while ((n = recvfrom(server_sock, buf, 65536, 0, (sockaddr *) &cliaddr, &socklen)) > 0) {
                    auto up = new Upstream();
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

                    if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr, sizeof(upserver_addr)) <
                        0) {
                        cerr << "send error" << endl;
                        if (bDaemon) syslog(LOG_WARNING, "sendto up stream error ");
                    }
                }
            } else if (events[_n].data.fd == upserver_sock) {
                while ((n = recv(upserver_sock, buf, max_udp_len, 0)) > 0) {
                    auto upstream = check(buf, n, (sockaddr *) &upserver_addr, sizeof(upserver_addr), false);
                    if (upstream == nullptr) continue;

                    *(uint16_t *) buf = htons(upstream->cli_id);
                    sendto(server_sock, buf, n, 0, (sockaddr *) &upstream->cliaddr, upstream->socklen);
                    id_map.erase(upstream->up_id);
                    delete upstream;
                    upstream = nullptr;
                }
            } else if (enable_tcp and events[_n].data.fd == server_sock_tcp) {
                for (;;) {
                    int newcon = accept(server_sock_tcp, (sockaddr *) &cliaddr, &socklen);
                    if (newcon < 0) {
                        if (errno != EAGAIN)
                            perror("accept error :");
                        if (bDaemon) syslog(LOG_WARNING, "accept error %d : %s", __LINE__, strerror(errno));
                        break;
                    }
                    // Accept new connnection from client
                    setnonblocking(newcon);
                    ev.events = EPOLLET | EPOLLIN | EPOLLERR;
                    ev.data.fd = newcon;
                    epoll_ctl(epollfd, EPOLL_CTL_ADD, newcon, &ev);
                    auto *up = new Upstream();
                    memcpy(&up->cliaddr, &cliaddr, socklen);
                    up->socklen = socklen;
                    up->cli_fd = newcon;
                    client_tcp_con[newcon] = up;
                }
            } else if (enable_tcp and client_tcp_con.find(events[_n].data.fd) != client_tcp_con.end()) {
                auto up = client_tcp_con[events[_n].data.fd];
                if (events[_n].events & EPOLLIN) {
                    read_buf(events[_n].data.fd, buf, up);
                    if (up->data_len == up->buf_len != 0) {
                        if (!add_upstream(up->buf, up->buf_len, up)) continue;
                        int upfd = socket(upserver_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
                        if (upfd < 0) {
                            perror("Can not open socket ");
                            if (bDaemon) syslog(LOG_ERR, "Can not open socket for listenning..");
                            exit(EXIT_FAILURE);
                        }
                        setnonblocking(upfd);
                        ev.events = EPOLLET | EPOLLOUT | EPOLLERR;
                        ev.data.fd = upfd;
                        epoll_ctl(epollfd, EPOLL_CTL_ADD, upfd, &ev);
                        int ret = connect(upfd, (sockaddr *) &upserver_addr, sizeof(upserver_addr));
                        if (ret < 0 and errno != EINPROGRESS) {
                            syslog(LOG_ERR, "connect to up server error %d : %s", __LINE__, strerror(errno));
                            return EXIT_FAILURE;
                        }
                        up->ser_fd = upfd;
                        server_tcp_con[upfd] = up;
                    }
                } else if (events[_n].events & EPOLLERR) {
                    close(events[_n].data.fd);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL,events[_n].data.fd, nullptr);
                    delete up;
                    client_tcp_con.erase(events[_n].data.fd);
                }

            } else if (enable_tcp and server_tcp_con.find(events[_n].data.fd) != server_tcp_con.end()) {
                int upfd = events[_n].data.fd;
                auto *up = server_tcp_con[upfd];
                if (events[_n].events & EPOLLOUT) {
                    // Connect succeed!

                    n = up->dns1.to_wire(buf + 2, max_udp_len - 2);
                    *(uint16_t *) buf = htons(n);
                    ssize_t siz = write(upfd, buf, n + 2);
                    if (siz != n + 2) {
                        perror("up write ");
                        return EXIT_FAILURE;
                    }
                    ev.events = EPOLLET | EPOLLIN | EPOLLERR;
                    ev.data.fd = upfd;
                    epoll_ctl(epollfd, EPOLL_CTL_MOD, upfd, &ev);
                    delete[] up->buf;
                    up->buf_len = up->data_len = 0;
                    up->buf = nullptr;
                    up->part_len = false;
                } else if (events[_n].events & EPOLLIN) {
                    read_buf(upfd, buf, up);
                    if (up->data_len == up->buf_len != 0) {
                        memcpy(buf + 2, up->buf, up->data_len);

                        auto upstream = check(buf + 2, up->data_len, (sockaddr *) &upserver_addr, sizeof(upserver_addr),
                                              true);
                        if (upstream == nullptr) continue;
                        *(uint16_t *) buf = htons(up->data_len);
                        *(uint16_t *) (buf + 2) = htons(upstream->cli_id);
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
                } else if (events[_n].events & EPOLLERR){
                    close(up->cli_fd);
                    close(up->ser_fd);
                    client_tcp_con.erase(up->cli_fd);
                    server_tcp_con.erase(up->ser_fd);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, up->cli_fd, nullptr);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, up->ser_fd, nullptr);
                    id_map.erase(up->up_id);
                    delete up;
                }


            } else if (events[_n].data.fd == tfd) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
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
                timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itimer, nullptr);
            } else if (events[_n].data.fd == sfd) {
                // need to check which signal was send
                if (bDaemon) syslog(LOG_INFO, "exit normally");
                goto end;
            }
        }
    }

    end:
    if (bDaemon) closelog();

    close(epollfd);
    close(server_sock);
    close(upserver_sock);
    cerr << "EXIT_SUCCESS" << endl;
    return EXIT_SUCCESS;
}
