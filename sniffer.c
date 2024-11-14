#ifdef __APPLE__
    #include <pcap/pcap.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <net/ethernet.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <signal.h>

    #define TCP_DEST(th)    ((th)->th_dport)
    #define TCP_SOURCE(th)  ((th)->th_sport)
    #define UDP_DEST(uh)    ((uh)->uh_dport)
    #define UDP_SOURCE(uh)  ((uh)->uh_sport)
#else
    #include <pcap.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <arpa/inet.h>
    #include <netinet/ether.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <signal.h>

    #define TCP_DEST(th)    ((th)->dest)
    #define TCP_SOURCE(th)  ((th)->source)
    #define UDP_DEST(uh)    ((uh)->dest)
    #define UDP_SOURCE(uh)  ((uh)->source)
#endif

#include "user_rules.h"

#define TAB1 "\t"
#define TAB2 "\t\t"

// Some stats to tracks
int totalPackets = 0;
int TCPPackets = 0;
int UDPPackets = 0;
/*
* Notes: 
* This make use of the LIBPCAP library. You can read more about it at https://github.com/the-tcpdump-group/libpcap or https://www.tcpdump.org/
* You'll need to install it with sudo dnf install libpcap-devel (or the equivalent for your operating system; this is for Fedora)
* Compile with: gcc -o sniffer sniffer.c -lpcap
* run with: sudo ./sniffer. 
* Naturally, this program requires elevated permissions 
* Use Ctrl C to exit
* ChatGPT helped significantly in learning how to use LIBPCAP and writing the structure of this program. 
*/

void PrintStats(int dummy);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Note: no user_rules file specified!\n");
    } else if (argc == 2) {
        parse_rules_file(argv[1]);
    } else  {
        fprintf(stderr, "Usage: %s <rules_file>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, PrintStats);
    char *device = pcap_lookupdev(NULL);
    if (device == NULL) {
        fprintf(stderr, "Could not find a default device\n");
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }

    printf("Listening on device %s...\n", device);
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);
    return 0;
}

void PrintStats(int dummy) {
    char *device = pcap_lookupdev(NULL);
    if (device == NULL) {
        fprintf(stderr, "Could not find a default device\n");
        return;
    }
    printf("\n");
    printf("************ STATS FOR %s ************\n", device);
    printf("Total Packets captured: %d\n", totalPackets);
    printf("Total TCP Packets captured: %d\n", TCPPackets);
    printf("Total UDP Packets captured: %d\n", UDPPackets);
    printf("Total None TCP/UDP packets captured: %d\n", totalPackets - (TCPPackets + UDPPackets));
    exit(0);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        int protocol = 0;
        uint16_t src_port = 0, dst_port = 0;

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            protocol = 1;
            src_port = ntohs(TCP_SOURCE(tcp_header));
            dst_port = ntohs(TCP_DEST(tcp_header));
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            protocol = 2;
            src_port = ntohs(UDP_SOURCE(udp_header));
            dst_port = ntohs(UDP_DEST(udp_header));
        }

        if (check_rules(src_ip, dst_ip, src_port, dst_port, protocol)) {
            totalPackets++;
            
            printf("Ethernet Header\n");
            printf("%sSource MAC: %s\n", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            printf("%sDestination MAC: %s\n", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            printf("%sProtocol: %u\n", TAB1, ntohs(eth_header->ether_type));

            printf("IP Header\n");
            printf("%sSource IP: %s\n", TAB1, src_ip);
            printf("%sDestination IP: %s\n", TAB1, dst_ip);

            if (protocol == 1) {
                printf("TCP Header\n");
                printf("%sSource Port: %u\n", TAB1, src_port);
                printf("%sDestination Port: %u\n", TAB1, dst_port);
                TCPPackets++;
            } else if (protocol == 2) {
                printf("UDP Header\n");
                printf("%sSource Port: %u\n", TAB1, src_port);
                printf("%sDestination Port: %u\n", TAB1, dst_port);
                UDPPackets++;
            }
            printf("\n");
        }
    }
}