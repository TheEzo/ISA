#include <iostream>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <cstdlib>
#include <cerrno>
#include <arpa/inet.h>
#include <ctime>
#include <signal.h>
#include <netdb.h>
#include <cstring>
#include <map>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <syslog.h>

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

using namespace std;

string get_name(const u_char *, const u_char *, int *);

string get_type(unsigned short);

string get_ipv6(const u_char *);

string get_local_ip();

string get_timestamp();

void read_response(const u_char *);

void sigusr_handler(int);

void mypcap_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void insert_message(string);

struct DNS_MESSAGE {
    short id; // identification // short is 2 bytes long

    // control - according to non-functional code and link 'bit numbering standarts' was each block of 8 bits reversed
    // reason is still unknown, but it works
    char rd : 1; // recursion desired
    char tc : 1; // truncated
    char aa : 1; // authorative answer
    char opcode : 4; // request type
    char qr : 1; // request/response

    char rcode : 4; // error codes
    char cd : 1; // checking disabled
    char ad : 1; // authenticated data
    char zeros : 1; // zeros
    char ra : 1; // recursion available

    // other fields
    unsigned short question_count;
    unsigned short answer_count;
    unsigned short authority_count;
    unsigned short additional_count;
};

struct QUESTION {
    unsigned short type;
    unsigned short cls;
};

struct ANSWER {
    unsigned short type;
    unsigned short cls;
    unsigned int ttl;
    unsigned short rdlength;
};

map<string, int> records;
map<string, int> syslog_records;
map<string, int>::iterator it;
char buffer[1025];
struct sockaddr_in serv_addr;
int socketfd;

int main(int argc, char **argv) {
    get_local_ip();
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    string r, i = "eth0", tmp;
    int t = 60, c;
    const u_char *packet;
    bool pr = false, pi = false, ps = false;
    struct hostent *server;
    pid_t pid;

    while ((c = getopt(argc, argv, "r:i:s:t:")) != -1)
        switch (c) {
            case 'r':
                pr = true;
                r = optarg;
                break;
            case 'i':
                pi = true;
                i = optarg;
                break;
            case 's': // setup connection to syslog server on -s
                if ((server = gethostbyname(optarg)) == nullptr) {
                    cerr << "Unknown syslog server" << endl;
                    return 1;
                }
                memset(&serv_addr, '0', sizeof(serv_addr));
                serv_addr.sin_family = AF_INET;
                bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr, (size_t) server->h_length);
                serv_addr.sin_port = htons(514);
                if ((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
                    cerr << "Socket creating failed" << endl;
                    return 1;
                }
                ps = true;
                break;
            case 't':
                t = atoi(optarg);
                break;
            case '?':
            default:
                cerr << "Unknown parameter" << endl;
                return 1;
        }
    if (pi && pr){
        cerr << "Cannot combine -i and -r" << endl;
        return 1;
    }

    signal(SIGUSR1, sigusr_handler);
    signal(SIGUSR2, sigusr_handler);

    if (pi) {
        // child that kill parent after specified time
        pid = fork();
        if (pid == 0) {
            while(1){
                sleep(t);
                kill(getppid(), SIGUSR2);
            }
        }
        /* tutorial from http://www.tcpdump.org/pcap.html */
        struct bpf_program fp;
        char filter_exp[] = "udp port 53 or tcp port 53";
        bpf_u_int32 mask;
        bpf_u_int32 net;

        if (pcap_lookupnet(i.c_str(), &net, &mask, errbuf) == -1) {
            cerr << "Can't get netmask for device " << i.c_str() << endl;
            return 1;
        }
        handle = pcap_open_live(i.c_str(), BUFSIZ, 0, t, errbuf);
        if (handle == NULL) {
            cerr << "Couldn't open device " << i.c_str() << ": " << errbuf << endl;
            return (2);
        }

        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
            return (2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
            return (2);
        }

        if (pcap_loop(handle, -1, mypcap_handler, NULL) == -1) {
            cerr << "pcap_loop() failed" << endl;
            return 1;
        }

        // close the capture device and deallocate resources
        pcap_close(handle);
    } else if (pr) {
        handle = pcap_open_offline(r.c_str(), errbuf);
        while ((packet = pcap_next(handle, &header)) != NULL) {
            read_response(packet);
        }
    }

    string msg;
    for (it = records.begin(); it != records.end(); it++) {
        if (ps) {
            strcpy(buffer, (get_timestamp() + " " + get_local_ip() + " <1> dns-export --- " + it->first + " " + to_string(it->second)).c_str());
            sendto(socketfd, buffer, strlen(buffer), 0, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in));
        } else {
            cout << it->first << " " << it->second << endl;
        }
    }

    return 0;
}

string get_local_ip(){
    char hostbuffer[256];
    struct hostent *host_entry;
    gethostname(hostbuffer, sizeof(hostbuffer));
    host_entry = gethostbyname(hostbuffer);
    string ip = inet_ntoa(*((struct in_addr *) host_entry->h_addr_list[0]));

    if (ip.rfind("127", 0) == 0)
        return host_entry->h_name;
    return ip;
}

void read_response(const u_char *packet) {
    struct ip *my_ip;
    struct ip6_hdr *my_ip6;
    struct ether_header *eptr = (struct ether_header *) packet;
    struct ANSWER *answer;
    struct DNS_MESSAGE *dns;
    struct tcphdr *tcp;

    u_int size, size_user_datagram_protocol, dns_pos;
    int len;

    switch (ntohs(eptr->ether_type)) {
        case ETHERTYPE_IPV6:
            my_ip6 = (struct ip6_hdr *) (packet + SIZE_ETHERNET);
            size = 40;
            switch ((int) my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                case 6: // tcp
                    tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + size);
                    size_user_datagram_protocol = tcp->doff * 4 + 2;
                    break;
                case 17: // udp
                    size_user_datagram_protocol = sizeof(struct udphdr);
                    break;
                default:
                    return;
            }
            break;
        case ETHERTYPE_IP: // IPv4 packet
            my_ip = (struct ip *) (packet + SIZE_ETHERNET);
            size = my_ip->ip_hl * 4;
            switch (my_ip->ip_p) {
                case 6: // TCP protocol
                    tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + size);
                    size_user_datagram_protocol = tcp->doff * 4 + 2;
                    break;
                case 17: // UDP protocol
                    size_user_datagram_protocol = sizeof(struct udphdr);
                    break;
                default: // unknown protocol
                    return;
            }
            break;
        default:
            return;
    }
    dns_pos = SIZE_ETHERNET + size + size_user_datagram_protocol;
    size = dns_pos; // size_ip is beginning of DNS struct now
    dns = (struct DNS_MESSAGE *) (packet + dns_pos);
    dns_pos += sizeof(struct DNS_MESSAGE);

    // question
    string name = get_name(packet + dns_pos, packet + size, &len);

    dns_pos += name.length() + 2 + sizeof(struct QUESTION);


    for (int i = 0; i < ntohs(dns->answer_count); i++) {
        len = 0;
        string ans_name = get_name(packet + dns_pos, packet + size, &len);
        if (!ans_name.length())
            return;

        answer = (struct ANSWER *) (packet + dns_pos + len);
        dns_pos += sizeof(struct ANSWER);
        ans_name += ' ' + get_type(ntohs(answer->type));
        switch (ntohs(answer->type)) {
            case 1: // a
                ans_name += ' ';
                for (int j = 0; j < 4; j++) {
                    unsigned char a = *(packet + dns_pos + j);
                    ans_name += to_string((int) a) + '.';
                }
                ans_name = ans_name.substr(0, ans_name.size() - 1);
                break;
            case 2: // ns
            case 5: // cname
            case 6: // soa
            case 47: // nsec
                len = ans_name.length();
                ans_name += ' ' + get_name(packet + dns_pos, packet + size, &len);
                if (len + 1 == ans_name.length())
                    return;
                break;
            case 28: // aaaa
                len = ans_name.length();
                ans_name += ' ' + get_ipv6(packet + dns_pos);
                if (len + 1 == ans_name.length())
                    return;
                break;
            case 46: // rrsig
                len = ans_name.length();
                ans_name += ' ' + get_name(packet + dns_pos + 18, packet + size, &len);
                if (len + 1 == ans_name.length())
                    return;
                break;
            case 15: // mx
                len = ans_name.length();
                ans_name += ' ' + get_name(packet + dns_pos + 2, packet + size, &len);
                if (len + 1 == ans_name.length())
                    return;
                break;
            case 16: // txt
            case 99: // spf
            default:
                ans_name = "";
                break;
        }
        if (!ans_name.empty())
            insert_message(ans_name);
        dns_pos += ntohs(answer->rdlength);
    }
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    read_response(packet);
}

string get_type(unsigned short num) {
    switch (num) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 28:
            return "AAAA";
        case 46:
            return "RRSIG";
        case 47:
            return "NSEC";
        case 99:
            return "SPF";
        default:
            return "UNDEFINED_" + to_string(num);
    }
}

string get_ipv6(const u_char *packet) {
    string result;
    for (int i = 0; i < 16; i++) {
        string tmp;
        stringstream s;
        s << hex << (int) *packet++;
        s >> tmp;
        while (tmp.size() < 2)
            tmp = "0" + tmp;
        result += tmp;
        if (i % 2)
            result += ":";
    }

    return result.substr(0, result.size() - 1);
}

string get_name(const u_char *packet, const u_char *dns_start, int *len) {
    string res = "";
    bool jump = false;

    while (*packet != '\0') {
        if ((int) *packet >= 192) {
            int offset = (*packet) * 256 + *(packet + 1) - 49152; //49152 = 11000000 00000000
            packet = dns_start + offset;
            jump = true;
            if (*len == 0)
                *len = 2;
        } else {
            int len = (int) *packet++;
            for (int i = 0; i < len; i++) {
                if (*packet == '\0')
                    return res.substr(0, res.size() - 1);
                res += *packet++;
            }
            res += ".";
        }
        if (!jump)
            (*len)++;
    }
    int printable = 0;
    for (auto &c: res)
        if (isprint(c))
            printable++;
    if (printable != res.size())
        return "";
    return res.substr(0, res.size() - 1);
}

void sigusr_handler(int signum) {
    if (signum == SIGUSR1) {
        for (it = records.begin(); it != records.end(); it++) {
            cout << it->first << " " << it->second << endl;
        }
    }
    if (signum == SIGUSR2) {
        for (it = syslog_records.begin(); it != syslog_records.end(); it++) {
            if (!it->second)
                continue;
            strcpy(buffer, ("timestamp " + get_local_ip() + " dns-export --- " + it->first + " " + to_string(it->second)).c_str());
            it->second = 0;
            sendto(socketfd, buffer, strlen(buffer), 0, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in));
        }
    }
}

void insert_message(string msg) {
    it = records.find(msg);
    if (it == records.end())
        records.insert({msg, 1});
    else
        it->second++;

    it = syslog_records.find(msg);
    if(it == syslog_records.end())
        syslog_records.insert({msg, 1});
    else
        it->second++;
}

string get_timestamp(){
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64];

    gettimeofday(&tv, NULL);
    string ms = to_string((tv.tv_sec) * 1000 + (tv.tv_usec) / 1000);
    ms = ms.substr(ms.size()-3, ms.size());
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    string res = tmbuf;
    return res + "." + ms.substr(0, 1) + "Z";
}

//%FT%T