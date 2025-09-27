#ifndef CAPTURE_H
#define CAPTURE_H

#include "utils.h"

#define MAX_PACKET_SIZE 65536
#define DEFAULT_BUFFER_SIZE 4096

// Packet capture statistics
typedef struct {
    unsigned long packets_captured;
    unsigned long packets_dropped;
    unsigned long bytes_captured;
    time_t start_time;
} capture_stats_t;

// Enhanced capture functions with proper error handling
pcap_result_t init_capture(const pcap_config_t* config, int* sock_fd);
pcap_result_t start_capture(const pcap_config_t* config);
pcap_result_t cleanup_capture(int sock_fd, unsigned char* buffer);
void print_capture_stats(const capture_stats_t* stats);

// Signal handling for graceful shutdown
extern volatile int should_stop;
void signal_handler(int signal);

#endif