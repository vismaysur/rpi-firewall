#ifdef __APPLE__
    #include <stdarg.h>
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
    #include <time.h>
    #include <string.h>

    #define TCP_DEST(th)    ((th)->th_dport)
    #define TCP_SOURCE(th)  ((th)->th_sport)
    #define UDP_DEST(uh)    ((uh)->uh_dport)
    #define UDP_SOURCE(uh)  ((uh)->uh_sport)
#else
    #include <stdarg.h>
    #include <pcap.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <arpa/inet.h>
    #include <netinet/ether.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <signal.h>
    #include <time.h>
    #include <string.h>

    #define TCP_DEST(th)    ((th)->dest)
    #define TCP_SOURCE(th)  ((th)->source)
    #define UDP_DEST(uh)    ((uh)->dest)
    #define UDP_SOURCE(uh)  ((uh)->source)
#endif

#ifdef __APPLE__
    char *device = "en0";
#else   
    char *device = NULL;
#endif

#include "../modules/user_rules.h"
#include "../modules/dos_detection.h"

#define TAB1 "\t"
#define TAB2 "\t\t"
#define MAX_LOG_BUFFER 1024

// Some stats to track
int totalPackets = 0;
int TCPPackets = 0;
int UDPPackets = 0;

// Log file handles
FILE *general_log = NULL;
FILE *dos_log = NULL;

// Function prototypes for logging
void init_logging();
void close_logging();
void log_message(const char *format, ...);
void log_dos_message(const char *format, ...);

void PrintStats(int dummy);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[]) {
    // Initialize logging first
    init_logging();

    if (argc == 1) {
        log_message("Note: no user_rules file specified!");
    } else if (argc == 2) {
        parse_rules_file(argv[1]);
    } else  {
        fprintf(stderr, "Usage: %s <rules_file>", argv[0]);
        close_logging();
        return 1;
    }

    initialize_dos_detection();

    signal(SIGINT, PrintStats);
    
    if (device == NULL) {
        device = pcap_lookupdev(NULL);
        if (device == NULL) {
            fprintf(stderr, "Could not find a default device");
            close_logging();
            return 1;
        }
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf("Could not open device %s: %s", device, error_buffer);
        close_logging();
        return 2;
    }

    log_message("Listening on device %s...", device);
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);
    close_logging();
    return 0;
}

void init_logging() {
    time_t now;
    struct tm *t;
    char timestamp[20];

    time(&now);
    t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", t);

    char general_log_filename[256];
    snprintf(general_log_filename, sizeof(general_log_filename), "logs/general/sniffer_log_%s.txt", timestamp);
    general_log = fopen(general_log_filename, "w");
    if (general_log == NULL) {
        perror("Error opening general log file");
        exit(1);
    }

    char dos_log_filename[256];
    snprintf(dos_log_filename, sizeof(dos_log_filename), "logs/dos_attacks/dos_attacks_%s.txt", timestamp);
    dos_log = fopen(dos_log_filename, "w");
    if (dos_log == NULL) {
        perror("Error opening DOS attack log file");
        fclose(general_log);
        exit(1);
    }
}

void close_logging() {
    if (general_log) {
        fclose(general_log);
        general_log = NULL;
    }
    if (dos_log) {
        fclose(dos_log);
        dos_log = NULL;
    }
}

void log_message(const char *format, ...) {
    if (!general_log) return;

    time_t now;
    struct tm *t;
    char timestamp[20];
    time(&now);
    t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char log_buffer[MAX_LOG_BUFFER];
    va_list args;
    va_start(args, format);
    
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    
    fprintf(general_log, "[%s] %s\n", timestamp, log_buffer);
    fflush(general_log);

    va_end(args);
}

void log_dos_message(const char *format, ...) {
    if (!dos_log) return;

    time_t now;
    struct tm *t;
    char timestamp[20];
    time(&now);
    t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char log_buffer[MAX_LOG_BUFFER];
    va_list args;
    va_start(args, format);
    
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    
    fprintf(dos_log, "[%s] %s\n", timestamp, log_buffer);
    fflush(dos_log);

    printf("[%s] %s\n", timestamp, log_buffer);

    va_end(args);
}

void PrintStats(int dummy) {
    if (device == NULL) {
        log_message("Could not find a default device");
        return;
    }
    
    log_message("************ STATS FOR %s ************", device);
    log_message("Total Packets captured: %d", totalPackets);
    log_message("Total TCP Packets captured: %d", TCPPackets);
    log_message("Total UDP Packets captured: %d", UDPPackets);
    log_message("Total None TCP/UDP packets captured: %d", totalPackets - (TCPPackets + UDPPackets));
    
    close_logging();
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

            track_potential_dos(src_ip);
            if (is_potential_dos_attack(src_ip)) {
                log_dos_message("POTENTIAL DOS ATTACK DETECTED FROM IP: %s", src_ip);
            }
            
            // Log Ethernet Header
            log_message("Ethernet Header");
            log_message("%sSource MAC: %s", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_shost));
            log_message("%sDestination MAC: %s", TAB1, ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
            log_message("%sProtocol: %u", TAB1, ntohs(eth_header->ether_type));

            // Log IP Header
            log_message("IP Header");
            log_message("%sSource IP: %s", TAB1, src_ip);
            log_message("%sDestination IP: %s", TAB1, dst_ip);

            if (protocol == 1) {
                log_message("TCP Header");
                log_message("%sSource Port: %u", TAB1, src_port);
                log_message("%sDestination Port: %u", TAB1, dst_port);
                TCPPackets++;
            } else if (protocol == 2) {
                log_message("UDP Header");
                log_message("%sSource Port: %u", TAB1, src_port);
                log_message("%sDestination Port: %u", TAB1, dst_port);
                UDPPackets++;
            }
            log_message("\n");
        }
    }
}