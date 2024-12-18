#pragma once

#include <stdint.h>
#include <time.h>

#define MAX_IP_ENTRIES 1024
#define DOS_THRESHOLD 100     // Packets per 5 seconds
#define DOS_TIME_WINDOW 5     // Time window in seconds

typedef struct {
    char ip[16];               // IP address string
    uint32_t packet_count;     // Packet count in current window
    time_t first_packet_time;  // Time of first packet in current window
} IPTrackEntry;

void initialize_dos_detection();
void track_potential_dos(const char* src_ip);
int is_potential_dos_attack(const char* src_ip);
void reset_dos_detection();