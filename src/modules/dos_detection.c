#include "dos_detection.h"
#include <string.h>
#include <time.h>

IPTrackEntry ip_track_table[MAX_IP_ENTRIES];
int ip_track_count = 0;

void initialize_dos_detection() {
    memset(ip_track_table, 0, sizeof(ip_track_table));
    ip_track_count = 0;
}

void track_potential_dos(const char* src_ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < MAX_IP_ENTRIES; i++) {
        if (strcmp(ip_track_table[i].ip, src_ip) == 0) {
            if ((current_time - ip_track_table[i].first_packet_time) <= DOS_TIME_WINDOW) {
                ip_track_table[i].packet_count++;
            } else {
                ip_track_table[i].first_packet_time = current_time;
                ip_track_table[i].packet_count = 1;
            }
            return;
        }
    }
    
    int empty_slot = -1;
    int oldest_index = 0;
    time_t oldest_time = ip_track_table[0].first_packet_time;
    
    for (int i = 0; i < MAX_IP_ENTRIES; i++) {
        if (strlen(ip_track_table[i].ip) == 0) {
            empty_slot = i;
            break;
        }
        
        if (ip_track_table[i].first_packet_time < oldest_time) {
            oldest_index = i;
            oldest_time = ip_track_table[i].first_packet_time;
        }
    }
    
    int index = (empty_slot != -1) ? empty_slot : oldest_index;
    
    strncpy(ip_track_table[index].ip, src_ip, sizeof(ip_track_table[index].ip) - 1);
    ip_track_table[index].first_packet_time = current_time;
    ip_track_table[index].packet_count = 1;
    
    if (empty_slot != -1 && ip_track_count < MAX_IP_ENTRIES) {
        ip_track_count++;
    }
}

int is_potential_dos_attack(const char* src_ip) {
    for (int i = 0; i < MAX_IP_ENTRIES; i++) {
        if (strcmp(ip_track_table[i].ip, src_ip) == 0) {
            return (ip_track_table[i].packet_count > DOS_THRESHOLD);
        }
    }
    return 0;
}

void reset_dos_detection() {
    initialize_dos_detection();
}