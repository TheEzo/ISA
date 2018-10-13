#include <iostream>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>


#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

using namespace std;

string get_name(const u_char *);
string get_type(unsigned short);
string get_ipv6(const u_char *);

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

struct QUESTION{
    unsigned short type;
    unsigned short cls;
};

struct ANSWER{
    unsigned short type;
    unsigned short cls;
    unsigned int ttl;
    unsigned short rdlength;
};

int main(int argc, char **argv) {
    vector<string> msg;
    pcap_t *handle;
    u_int size_ip;
    u_int size_user_datagram_protocol;
    struct ip *my_ip;
    char errbuf[PCAP_ERRBUF_SIZE];
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    const struct udphdr *my_udp;    // pointer to the beginning of UDP header
    struct pcap_pkthdr header;
    struct ether_header *eptr;
    std::string r, i, s;
    int t = 60;
    const u_char *packet;
    bool pr = false, pi = false, ps = false, pt = false;
    int c;

    struct DNS_MESSAGE *record = nullptr;
    struct ANSWER *answer = nullptr;

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
            case 's':
                ps = true;
                s = optarg;
                break;
            case 't':
                pt = true;
                t = stoi(optarg);
                break;
            case '?':
            default:
                cerr << "Unknown parameter" << endl;
                return 1;
        }

    if (pr) {
        handle = pcap_open_offline(r.c_str(), errbuf);

        while ((packet = pcap_next(handle, &header)) != NULL) {
            eptr = (struct ether_header *) packet;
            switch (ntohs(eptr->ether_type)) {
                case ETHERTYPE_IP: // IPv4 packet
                    my_ip = (struct ip *) (packet + SIZE_ETHERNET);
                    size_ip = my_ip->ip_hl * 4;
                    switch (my_ip->ip_p) {
                        case 2: // IGMP protocol
                            continue;
                        case 6: // TCP protocol
                            my_tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + size_ip); // pointer to the TCP header
                            size_user_datagram_protocol = sizeof(struct tcphdr);
                            break;
                        case 17: // UDP protocol
                            my_udp = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip); // pointer to the UDP header
                            size_user_datagram_protocol = sizeof(*my_udp);
                            break;
                        default: // unknown protocol
                            continue;
                    }
                    record = (struct DNS_MESSAGE *) (packet + SIZE_ETHERNET + size_ip + size_user_datagram_protocol);

                    if (ntohs(record->answer_count) > 0) {
                        size_t index = SIZE_ETHERNET + size_ip + size_user_datagram_protocol + sizeof(struct DNS_MESSAGE);
                        string name = get_name(packet + index);
                        index += name.length() + 2;
                        index += sizeof(struct QUESTION);

                        string ans_name = get_name(packet + index);
                        index += ans_name.length() ? ans_name.length() : 2;
                        ans_name = ans_name.length() ? ans_name : name;

                        answer = (struct ANSWER *) (packet + index);
                        index += sizeof(struct ANSWER) - 2;
                        ans_name += ' ' + get_type(ntohs(answer->type));
                        switch(ntohs(answer->type)){
                            case 1:
                                for(int i = 0; i < 4; i++){
                                    unsigned char a = *(packet + index + i);
                                    ans_name += ' ' + to_string((int)a) + '.';
                                }
                                ans_name = ans_name.substr(0, ans_name.size()-1);
                                break;
                            case 28:
                                ans_name +=  ' ' + get_ipv6(packet + index);
                                break;
                            default:
                                break;
                        }
                        msg.push_back(ans_name);
                    }
                    break;

                default:
                    break;
            }
        }
    }
    if (ps){

    }
    else{
        for(auto record: msg)
            cout << record << endl;
    }

    return 0;
}

string get_type(unsigned short num){
    switch(num){
        case 1:
            return "A";
        case 28:
            return "AAAA";
        default:
            return "UNDEFINED";
    }
}

string get_ipv6(const u_char * packet){
    string result;
    bool pair = false;
    for(int i = 0; i < 16; i++){
        string tmp;
        stringstream s;
        s << hex << (int)*packet++;
        s >> tmp;
        result += tmp;
        if(i % 2){
            pair = true;
            result += ":";
        }
        else
            pair = false;
    }
    return result.substr(0, result.size()-1);
}

string get_name(const u_char *packet){
    // detect c0 0c
    if ((int)*packet == 192 && *(packet + 1) == 12)
        return "";
    string res = "";
    while(true){
        int len = (int)*packet++;
        for(int i = 0; i < len; i++){
            res += *packet++;
        }
        res += ".";
        if (*packet == '\0')
            return res.substr(0, res.size()-1);
    }
}