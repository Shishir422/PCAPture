#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

// Configuration structure
typedef struct {
    char interface[16];      // Network interface to capture from
    char log_file[256];      // Log file path
    int packet_limit;        // Maximum packets to capture (0 = unlimited)
    bool verbose;            // Verbose output
    bool drop_privileges;    // Whether to drop root privileges
    int target_uid;          // UID to drop to
    int target_gid;          // GID to drop to
    char filter[512];        // Packet filter expression
} pcap_config_t;

// Return codes
typedef enum {
    PCAP_SUCCESS = 0,
    PCAP_ERROR_SOCKET = -1,
    PCAP_ERROR_MEMORY = -2,
    PCAP_ERROR_PRIVILEGE = -3,
    PCAP_ERROR_INVALID_PARAM = -4,
    PCAP_ERROR_BUFFER_OVERFLOW = -5,
    PCAP_ERROR_PARSE = -6
} pcap_result_t;

// Utility functions
pcap_result_t drop_privileges(int uid, int gid);
pcap_result_t validate_buffer_bounds(const void* buffer, size_t buffer_size, size_t required_size);
void secure_zero_memory(void* ptr, size_t size);
pcap_result_t safe_string_copy(char* dest, size_t dest_size, const char* src);
void log_message(const char* level, const char* format, ...);
void setup_signal_handlers(void);

// Configuration management
pcap_result_t load_config(pcap_config_t* config, const char* config_file);
void init_default_config(pcap_config_t* config);
void print_config(const pcap_config_t* config);

#endif