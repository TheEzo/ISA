#include <iostream>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ctime>
#include <signal.h>
#include <netdb.h>
#include <cstring>


#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

using namespace std;

string get_name(const u_char *, int);

string get_type(unsigned short);

string get_ipv6(const u_char *);

string read_response(const u_char *);

void sigusr1_handler(int);

void mypcap_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

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

vector<string> msg;

int main(int argc, char **argv) {
    pcap_t *handle;
    struct ip *my_ip;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct ether_header *eptr;
        string r, i, tmp;
    int t = 60, c, socketfd;
    const u_char *packet;
    bool pr = false, pi = false, ps = false;
    struct sockaddr_in serv_addr;
    hostent *server;
    char buffer[1025];
    strcpy(buffer,  "testovaci zprava");

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
//                if ((server = gethostbyname(optarg)) == nullptr){
//                    cerr << "Unknown syslog server" << endl;
//                    return 1;
//                }
//                memset(&serv_addr, '0', sizeof(serv_addr));
//                serv_addr.sin_family = AF_INET;
//                serv_addr.sin_addr.s_addr = inet_addr("192.168.2.2");
//                serv_addr.sin_port = htons(514);
//                if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) <= 0){
//                    cerr << "Socket creating failed" << endl;
//                    return 1;
//                }
//                if(connect(socketfd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0){
//                    cerr << "Connecting failed" << endl;
//                    return 1;
//                }
//                send(socketfd, buffer, strlen(buffer), 0);
//                close(socketfd);
                openlog("dns-export", LOG_PID, LOG_LOCAL0);
                syslog(LOG_INFO, "test log msg");
                exit(0);
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

    signal(SIGUSR1, sigusr1_handler);

    if (pi) {
        /* tutorial from http://www.tcpdump.org/pcap.html */
        struct bpf_program fp;
        char filter_exp[] = "udp port 53";
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
            tmp = read_response(packet);
            if (tmp.size())
                msg.push_back(tmp);
        }
    }

    if (ps) {

    } else {
        for (auto record: msg)
            cout << record << endl;
    }

    return 0;
}

string read_response(const u_char *packet) {
    struct ip *my_ip;
    struct ether_header *eptr = (struct ether_header *) packet;
    struct ANSWER *answer;
    struct DNS_MESSAGE *dns;

    u_int size_ip, size_user_datagram_protocol, dns_pos;

    switch (ntohs(eptr->ether_type)) {
        case ETHERTYPE_IP: // IPv4 packet
            my_ip = (struct ip *) (packet + SIZE_ETHERNET);
            size_ip = my_ip->ip_hl * 4;
            switch (my_ip->ip_p) {
                case 17: // UDP protocol
                    size_user_datagram_protocol = sizeof(struct udphdr);
                    break;
                default: // unknown protocol
                    return "";
            }
            dns_pos = SIZE_ETHERNET + size_ip + size_user_datagram_protocol;
            size_ip = dns_pos; // size_ip is beginning of DNS struct now
            dns = (struct DNS_MESSAGE *) (packet + dns_pos);

            if (ntohs(dns->answer_count) > 0) {
                dns_pos += sizeof(struct DNS_MESSAGE);
                string name = get_name(packet + dns_pos, 0);
                dns_pos += name.length() + 2 + sizeof(struct QUESTION);

                string ans_name = get_name(packet + dns_pos, 0);
                dns_pos += ans_name.length() ? ans_name.length() : 2;
                ans_name = ans_name.length() ? ans_name : name;

                answer = (struct ANSWER *) (packet + dns_pos);
                dns_pos += sizeof(struct ANSWER) - 2;
                ans_name += ' ' + get_type(ntohs(answer->type));
                switch (ntohs(answer->type)) {
                    case 1: // a
                        ans_name += ' ';
                        for (int i = 0; i < 4; i++) {
                            unsigned char a = *(packet + dns_pos + i);
                            ans_name += to_string((int) a) + '.';
                        }
                        ans_name = ans_name.substr(0, ans_name.size() - 1);
                        break;
                    case 5: // cname
                        ans_name += ' ' + get_name(packet + dns_pos, size_ip);
                        break;
                    case 28: // aaaa
                        ans_name += ' ' + get_ipv6(packet + dns_pos);
                        break;
                    default:
                        break;
                }
                return ans_name;
            }
            break;
        default:
            return "";
    }

    return "";
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    string tmp = read_response(packet);
    if (tmp.size())
        msg.push_back(tmp);
}

string get_type(unsigned short num) {
    switch (num) {
        case 1:
            return "A";
        case 5:
            return "CNAME";
        case 28:
            return "AAAA";
        default:
            return "UNDEFINED";
    }
}

string get_ipv6(const u_char *packet) {
    string result;
    bool pair = false;
    for (int i = 0; i < 16; i++) {
        string tmp;
        stringstream s;
        s << hex << (int) *packet++;
        s >> tmp;
        while(tmp.size() < 2)
            tmp = "0" + tmp;
        result += tmp;
        if (i % 2)
            result += ":";
    }

    return result.substr(0, result.size() - 1);
}

string get_name(const u_char *packet, int prev) {
    if ((int) *packet == 192 && *(packet + 1) == 12) // c0 0c
        return "";
    bool jump = !prev;
    string res = "";
    const u_char *start = packet;
    while (true) {
        int len = (int) *packet++;
        for (int i = 0; i < len; i++) {
            if (*packet == '\0')
                return res.substr(0, res.size() - 1);
            res += *packet++;
        }
        if((int)*packet>=192 && !jump){ // c0 ..
            // offset from https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
            int offset = (*packet)*256 + *(packet+1) - 49152; //49152 = 11000000 00000000
            packet = start - prev + offset - 2;
            jump = true;
        }
        res += ".";
        if (*packet == '\0')
            return res.substr(0, res.size() - 1);
    }
}

void sigusr1_handler(int signum){
    if (signum == SIGUSR1){
        for(auto text: msg)
            cout << text << endl;
        exit(0);
    }
}
