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

    ssize_t to_wire(char *buf);

    vector<Question> questions;
    vector<Answer> answers;
    vector<Additional> additionals;


    string getName(char *&ptr, char *buf);

    char *toName(string &name, char *ptr, const char *buf, unordered_map<string, uint16_t> &str_map);

    unsigned short id;
    unsigned short signs;

    bool GFW_mode = true;
private:
    uint16_t ntohs_ptr(char *&ptr) {
        uint16_t value = ntohs(*(uint16_t *) ptr);
        ptr += 2;
        return value;
    }

    uint32_t ntohl_ptr(char *&ptr) {
        uint32_t value = ntohl(*(uint32_t *) ptr);
        ptr += 4;
        return value;
    }

    void htons_ptr(char *&ptr, uint16_t value) {
        *(uint16_t *) ptr = htons(value);
        ptr += 2;
    }

    void htonl_ptr(char *&ptr, uint32_t value) {
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
    unsigned short qdcout;
    unsigned short ancout;
    unsigned short nscout;
    unsigned short arcout;
    id = ntohs_ptr(ptr);
    signs = ntohs_ptr(ptr);
    qdcout = ntohs_ptr(ptr);
    ancout = ntohs_ptr(ptr);
    nscout = ntohs_ptr(ptr);
    arcout = ntohs_ptr(ptr);
    for (unsigned short i = 0; i < qdcout; i++) {
        Question question;
        question.name = getName(ptr, buf);
        question.Type = (QType) ntohs_ptr(ptr);
        question.Class = (QClass) ntohs_ptr(ptr);
        questions.push_back(question);
    }
    for (unsigned short i = 0; i < ancout; i++) {
        Answer answer;
        answer.name = getName(ptr, buf);
        answer.Type = (QType) ntohs_ptr(ptr);
        answer.Class = (QClass) ntohs_ptr(ptr);
        answer.TTL = ntohl_ptr(ptr);
        uint16_t RDLENGTH = ntohs_ptr(ptr);
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
                answer.rdata = getName(ptr, buf);
        }

        answers.push_back(answer);
    }
//    for (unsigned short i = 0; i < arcout; i++) {
//        Additional additional;
//        additional.name = *ptr;
//        ptr++;
//        additional.Type = ntohs_ptr(*(uint16_t *) ptr);
//        ptr += 2;
//        additional.playload_size = ntohs_ptr(*(uint16_t *) ptr);
//        ptr += 2;
//        additional.high_bit_in_extend_rcode = *ptr;
//        ptr++;
//        additional.edns0_verion = *ptr;
//        ptr++;
//        additional.Z = ntohs_ptr(*(uint16_t *) ptr);
//        ptr += 2;
//        additional.data_length = ntohs_ptr(*(uint16_t *) ptr);
//        ptr += 2;
//        additionals.push_back(additional);
//    }
}

char *dns::toName(string &name, char *ptr, const char *buf, unordered_map<string, uint16_t> &str_map) {
    char *now_ptr = ptr;
    uint8_t sublen = 0;
    size_t pos = 0;
    try {
        uint16_t off = str_map.at(name.substr(pos));
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
                *now_ptr = sublen;
            }
            sublen = 0;
            pos++;
            try {
                uint16_t off = str_map.at(name.substr(pos));
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

string dns::getName(char *&ptr, char *buf) {
    string name;
    bool first = true;
    while (true) {
        unsigned char count = *ptr;

        char *locate;
        if (count & 0xc0) {
            // compressed label
            locate = buf + 256 * (count & 0x3f) + *(ptr + 1);
            if (!first) name.append(1, '.');
            else first = false;
            name += getName(locate, buf);
            ptr += 2;
            break;
        } else {
            locate = ptr;
            ptr += count + 1;
        }
        if (count > 0) {
            if (!first) name.append(1, '.');
            else first = false;
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


ssize_t dns::to_wire(char *buf) {
    unordered_map<string, uint16_t> str_map;
    char *ptr = buf;
    htons_ptr(ptr, id);
    htons_ptr(ptr, signs);
    if (!(signs & QR) and GFW_mode) {
        htons_ptr(ptr, 2);
    } else {
        htons_ptr(ptr, questions.size());
    }
    htons_ptr(ptr, answers.size());
    htons_ptr(ptr, 0);
    htons_ptr(ptr, 0);
    if (!(signs & QR) and GFW_mode) {
        htons_ptr(ptr, 0xc012);
        htons_ptr(ptr, questions[0].Type);
        htons_ptr(ptr, questions[0].Class);
    }
    for (auto &q : questions) {
        char *new_ptr = toName(q.name, ptr, buf, str_map);
        ptr = new_ptr;
        htons_ptr(ptr, q.Type);
        htons_ptr(ptr, q.Class);
    }
    for (auto &ans : answers) {
        ptr = toName(ans.name, ptr, buf, str_map);
        htons_ptr(ptr, ans.Type);
        htons_ptr(ptr, ans.Class);
        htonl_ptr(ptr, ans.TTL);
        switch (ans.Type) {
            case A:
                htons_ptr(ptr, sizeof(in_addr));
                inet_pton(AF_INET, ans.rdata.c_str(), ptr);
                ptr += sizeof(struct in_addr);
                break;
            case AAAA:
                htons_ptr(ptr, sizeof(in6_addr));
                inet_pton(AF_INET6, ans.rdata.c_str(), ptr);
                ptr += sizeof(struct in6_addr);
                break;
            default:
                char *len_ptr = ptr;
                ptr += 2;
                char *new_ptr = toName(ans.rdata, ptr, buf, str_map);
                *(uint16_t *) len_ptr = htons(new_ptr - ptr);
                ptr = new_ptr;
        }
    }
    for (auto &add : additionals) {
        *ptr = add.name;
        ptr++;
        htons_ptr(ptr, add.Type);
        htons_ptr(ptr, add.playload_size);
        *ptr = add.high_bit_in_extend_rcode;
        ptr++;
        *ptr = add.edns0_verion;
        ptr++;
        htons_ptr(ptr, add.Z);
        htons_ptr(ptr, add.data_length);
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
    cerr << "Usage: " << argv[0] << " [-d] [-u user] [-6] [-g] -l local_address -p local_port -r remote_address"
         << endl;
    cerr << "-6 : ipv6 first" << endl;
    cerr << "-d : daemon mode" << endl;
    cerr << "-g : great firewall mode" << endl;
}

int main(int argc, char *argv[]) {

    char *local_address = nullptr;
    uint16_t local_port = 0;
    char *remote_address = nullptr;
    bool bDaemon = false;
    char *new_user = nullptr;
    bool ipv6_first = false;
    bool gfw_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "6gu:dl:p:r:")) != -1) {
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
            case 'p':
                local_port = atoi(optarg);
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
    setnonblocking(server_sock);

    struct sockaddr_storage upserver_addr;
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
    int upserver_sock = socket(upserver_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
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

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = upserver_sock;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, upserver_sock, &ev);

    int tfd = timerfd_create(CLOCK_MONOTONIC_COARSE, 0);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = tfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, tfd, &ev);

    sigset_t mask;

    struct signalfd_siginfo fdsi;
    ssize_t s;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGTERM);

    /* Block signals so that they aren't handled
       according to their default dispositions */

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


    class Upstream {
    public:
        uint16_t cli_id;
        sockaddr_storage cliaddr;
        socklen_t socklen;
        bool checked_ipv6;
        dns dns1;
        Upstream *prev, *next;
        struct timespec time;
        uint16_t up_id;
    };

    unordered_map<uint16_t, Upstream *> id_map;
    Upstream *oldest_up = nullptr, *newest_up = nullptr;

    struct itimerspec itimer;
    itimer.it_interval.tv_nsec = 0;
    itimer.it_interval.tv_sec = 0;
    for (;;) {
        int nfds = epoll_wait(epollfd, events, 10, -1);
        for (int _n = 0; _n < nfds; ++_n) {
            if (events[_n].data.fd == server_sock) {
                while ((n = recvfrom(server_sock, buf, 65536, 0, (sockaddr *) &cliaddr, &socklen)) > 0) {
                    auto *upstream = new Upstream();
                    upstream->dns1.from_wire(buf, n);
                    if (upstream->dns1.questions.empty()) {
                        delete upstream;
                        continue;
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
                    if (ipv6_first and gfw_mode) {
                        n = upstream->dns1.to_wire(buf);
                    }
                    upstream->cli_id = ntohs(*(uint16_t *) buf);
                    uint16_t new_id = get_id();
                    upstream->up_id = new_id;
                    *(uint16_t *) buf = htons(new_id);
                    memcpy(&upstream->cliaddr, &cliaddr, socklen);
                    upstream->socklen = socklen;
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
                    if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr, sizeof(upserver_addr)) < 0) {
                        cerr << "send error" << endl;
                        if (bDaemon) syslog(LOG_WARNING, "sendto up stream error ");
                    }
                    id_map[new_id] = upstream;
                }
            } else if (events[_n].data.fd == upserver_sock) {
                while ((n = recv(upserver_sock, buf, max_udp_len, 0)) > 0) {
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
                            dns dns1(buf, n);
                            for (auto &ans : dns1.answers) {
                                if (ans.Type == dns::AAAA) {
                                    upstream->checked_ipv6 = true;
                                    break;
                                }
                            }
                            if (upstream->checked_ipv6) {
                                dns1.questions[0].Type = dns::A;
                                n = dns1.to_wire(buf);
                            } else {
                                upstream->checked_ipv6 = true;
                                upstream->dns1.questions[0].Type = dns::A;
                                upstream->dns1.id = get_id();
                                upstream->up_id = upstream->dns1.id;
                                n = upstream->dns1.to_wire(buf);
                                if (sendto(upserver_sock, buf, n, 0, (sockaddr *) &upserver_addr,
                                           sizeof(upserver_addr)) < 0) {
                                    if (bDaemon) syslog(LOG_WARNING, "send to client error");
                                    cerr << "send error" << endl;
                                }
                                id_map[upstream->dns1.id] = upstream;
                                id_map.erase(it);
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
                                continue;
                            }
                        }
                        *(uint16_t *) buf = htons(upstream->cli_id);
                        sendto(server_sock, buf, n, 0, (sockaddr *) &upstream->cliaddr, upstream->socklen);
                        id_map.erase(it);
                        delete upstream;
                        upstream = nullptr;

                    }
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
