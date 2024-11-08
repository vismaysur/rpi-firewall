#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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


void PrintStats() {
    char *device = pcap_lookupdev(NULL);
    if (device == NULL) {
        fprintf(stderr, "Could not find a default device\n");
        return;
    }
    printf("************ STATS FOR %s ************\n", device);
    printf("Total Packets captured: %d\n", totalPackets);
    printf("Total TCP Packets captured: %d\n", TCPPackets);
    printf("Total UDP Packets captured: %d\n", UDPPackets);
    printf("Total None TCP/UDP packets captured: %d\n", totalPackets - (TCPPackets + UDPPackets));
    
}
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Ethernet header
    totalPackets++;
    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("Ethernet Header\n");
    printf("%sSource MAC: %s\n", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_shost));
    printf("%sDestination MAC: %s\n", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
    printf("%sProtocol: %u\n", TAB1, ntohs(eth_header->ether_type));

    // Check if the packet contains an IP header
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("IP Header\n");
        printf("%sSource IP: %s\n", TAB1, inet_ntoa(ip_header->ip_src));
        printf("%sDestination IP: %s\n", TAB1, inet_ntoa(ip_header->ip_dst));

        // We only check for TCP or UDP
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            printf("TCP Header\n");
            printf("%sSource Port: %u\n", TAB1, ntohs(tcp_header->source));
            printf("%sDestination Port: %u\n", TAB1, ntohs(tcp_header->dest));
            TCPPackets++;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            printf("UDP Header\n");
            printf("%sSource Port: %u\n", TAB1, ntohs(udp_header->source));
            printf("%sDestination Port: %u\n", TAB1, ntohs(udp_header->dest));
            UDPPackets++;
        } else {
            printf("Found non TCP/UDP packet with IP header.\n");
        }
    } else {
        printf("Found packet without IP header.\n");
    }
    printf("\n");
}

int main() {
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
