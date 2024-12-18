#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_RULES       100
#define MAX_LINE_LEN    256

struct Rule {
    int         protocol_t;     // 1: TCP, 2: UDP, 0: both
    char        ip_src[16];
    char        ip_dst[16];
    uint16_t    port_src;
    uint16_t    port_dst;
    int         filter;         // 0: block, 1: allow
};

int is_ip_match(const char *rule_ip, const char *packet_ip);

int is_port_match(uint16_t rule_port, uint16_t packet_port);

void parse_rules_file(const char* filename);

int check_rules(const char* ip_src, const char* ip_dst, uint16_t port_src, uint16_t port_dst, int protocol);