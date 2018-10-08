#include <iostream>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <cstdlib>
#include <cstring>

using namespace std;



int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
//    struct pcap_pkthdr header;
    std::string r, i, s, t;
    const u_char *packet;
    bool pr = false, pi = false, ps = false, pt = false;
    int c;
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
                t = optarg;
                break;
            case '?':
            default:
                cerr << "Unknown parameter" << endl;
                return 1;
        }

    if (pr){
        int count = 0;
//        if ((handle = pcap_open_offline(r, errbuf)) == NULL)
//            exit(1);
//        while ((packet = pcap_next(handle,&header)) != NULL){
//            printf("Packet # %i\n", ++count);
//
//            // Show the size in bytes of the packet
//            printf("Packet size: %d bytes\n", header->len);
//
//            // Show a warning if the length captured is different
//            if (header->len != header->caplen)
//                printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
//
//            // Show Epoch Time
//            printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
//
//            // loop through the packet and print it as hexidecimal representations of octets
//            // We also have a function that does this similarly below: PrintData()
//            for (u_int i=0; (i < header->caplen ) ; i++)
//            {
//                // Start printing on the next after every 16 octets
//                if ( (i % 16) == 0) printf("\n");
//
//                // Print each octet as hex (x), make sure there is always two characters (.2).
//                printf("%.2x ", data[i]);
//            }
//
//            // Add two lines between packets
//            printf("\n\n");
//        }
        struct pcap_pkthdr *header;
        const u_char *data;
        u_int packetCount = 0;
        handle = pcap_open_offline(r.c_str(), errbuf);
        while (int returnValue = pcap_next_ex(handle, &header, &data) >= 0)
        {
            // Print using printf. See printf reference:
            // http://www.cplusplus.com/reference/clibrary/cstdio/printf/

            // Show the packet number
            printf("Packet # %i\n", ++packetCount);

            // Show the size in bytes of the packet
            printf("Packet size: %d bytes\n", header->len);

            // Show a warning if the length captured is different
            if (header->len != header->caplen)
                printf("Warning! Capture size different than packet size: %ld bytes\n", static_cast<long>(header->len));

            // Show Epoch Time
            printf("Epoch Time: %d:%d seconds\n", static_cast<int>(header->ts.tv_sec),
                   static_cast<int>(header->ts.tv_usec));

            // loop through the packet and print it as hexidecimal representations of octets
            // We also have a function that does this similarly below: PrintData()
            for (u_int i=0; (i < header->caplen ) ; i++)
            {
                // Start printing on the next after every 16 octets
                if ( (i % 16) == 0) printf("\n");

                // Print each octet as hex (x), make sure there is always two characters (.2).
                printf("%.2x ", data[i]);
            }

            // Add two lines between packets
            printf("\n\n");
        }
    }
    return 0;
}