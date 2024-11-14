#include "user_rules.h"

struct Rule rules[MAX_RULES];
int rule_count = 0;

int is_ip_match(const char *rule_ip, const char *packet_ip) {
    if (strcmp(rule_ip, "*") == 0) return 1;
    return (strcmp(rule_ip, packet_ip) == 0);
}

int is_port_match(uint16_t rule_port, uint16_t packet_port) {
    if (rule_port == 0) return 1;
    return (rule_port == packet_port);
}

void parse_rules_file(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening rules file %s", filename);
        exit(1);
    }

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), file) && rule_count < MAX_RULES) {
        if (line[0] == '\n' && line[0] == '#') continue;

        char protocol[10], ip_src[16], ip_dst[16];
        int  port_src, port_dst;

        // Format: protocol ip_src port_src ip_dst port_dst action
        // Example: TCP 192.168.1.* 80 * 0 allow
        if (sscanf(line, "%s %s %d %s %d %s", protocol, ip_src, &port_src, 
                  ip_dst, &port_dst, line) == 6) {
            
            rules[rule_count].port_src = port_src;
            rules[rule_count].port_dst = port_dst;
            strncpy(rules[rule_count].ip_src, ip_src, 16);
            strncpy(rules[rule_count].ip_dst, ip_dst, 16);
            
            if (strcasecmp(protocol, "TCP") == 0) {
                rules[rule_count].protocol_t = 1;
            } else if (strcasecmp(protocol, "UDP") == 0) {
                rules[rule_count].protocol_t = 2;
            } else {
                rules[rule_count].protocol_t = 0;
            }
            
            rules[rule_count].filter = (strcasecmp(line, "allow") == 0) ? 1 : 0;

            rule_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d rules from %s\n", rule_count, filename);
}

int check_rules(const char* ip_src, const char* ip_dst, uint16_t port_src, uint16_t port_dst, int protocol) {
    for (int i = 0; i < rule_count; i++) {
        if (rules[i].protocol_t != 0 && rules[i].protocol_t != protocol) continue;

        if (is_ip_match(rules[i].ip_src, ip_src) &&
            is_ip_match(rules[i].ip_dst, ip_dst) &&
            is_port_match(rules[i].port_src, port_src) &&
            is_port_match(rules[i].port_dst, port_dst)) {
            return rules[i].filter;
        }
    }
    
    return 1;
}   