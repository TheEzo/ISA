/*******************************
 * ISA - project               *
 * 2018/2019                   *
 * Tomas Willaschek            *
 * xwilla00                    *
 *******************************/

#ifndef ISA_DNS_EXPORT_H
#define ISA_DNS_EXPORT_H

#include <iostream>
#include <map>
#include <netinet/in.h>

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

using namespace std;

/**
 * Parse name from dns response
 * @param packet: index to name start byte
 * @param dns_start: index to start of dns struct - for jumps
 * @param len: address of variable where is stored result name length
 * @return <string> name
 */
string get_name(const u_char *, const u_char *, int *);

/**
 * Get type of response
 * @param num: number of type
 * @return <string> type - e.g. A or AAAA
 */
string get_type(unsigned short);

/**
 * Parse IPv6 from response
 * @param packet: IPv6 start byte
 * @return <strint> IPv6
 */
string get_ipv6(const u_char *);

/**
 * Gets IP of current machine
 * @return <string> IP
 */
string get_local_ip();

/**
 * Gets actuall time parsed into timestamp format YYY-mm-ddTHH:MM:SS.ssZ
 * @return <string> timestamp
 */
string get_timestamp();

/**
 * Reads single response packet
 * parse all headers and dns struct
 * @param packet: start byte of packet
 */
void read_response(const u_char *);

/**
 * Process saved data and sends it to syslog or stdout
 * @param signum: signal number
 */
void sigusr_handler(int);

/**
 * Function called as handler for pcap_loop()
 */
void mypcap_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

/**
 * Inserts message to maps or increment message count
 * @param msg
 */
void insert_message(string);

/**
 * DNS structure
 */
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

/**
 * DNS question structure
 */
struct QUESTION {
    unsigned short type;
    unsigned short cls;
};

/**
 * DNS answer structure
 */
struct ANSWER {
    unsigned short type;
    unsigned short cls;
    unsigned int ttl;
    unsigned short rdlength;
};

/**
 * Total records count
 */
map<string, int> records;

/**
 * Records count - every logging to syslog sets count to zero
 */
map<string, int> syslog_records;

/**
 * Iterator for map defined above
 */
map<string, int>::iterator it;

/**
 * Buffer for UPD message sender
 */
char buffer[1025];

/**
 * Syslog server address
 */
struct sockaddr_in serv_addr;

/**
 * Syslog server file descriptor
 */
int socketfd = 0;

#endif //ISA_DNS_EXPORT_H
