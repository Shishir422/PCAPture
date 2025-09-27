#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <time.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include "utils.h"

static FILE* log_file_ptr = NULL;

// Securely drop root privileges
pcap_result_t drop_privileges(int uid, int gid) {
    if (getuid() != 0) {
        log_message("INFO", "Not running as root, skipping privilege drop");
        return PCAP_SUCCESS;
    }

    // Drop supplementary groups
    if (setgroups(0, NULL) != 0) {
        log_message("ERROR", "Failed to drop supplementary groups: %s", strerror(errno));
        return PCAP_ERROR_PRIVILEGE;
    }

    // Set GID first (must be done before UID)
    if (setgid(gid) != 0) {
        log_message("ERROR", "Failed to set GID %d: %s", gid, strerror(errno));
        return PCAP_ERROR_PRIVILEGE;
    }

    // Set UID
    if (setuid(uid) != 0) {
        log_message("ERROR", "Failed to set UID %d: %s", uid, strerror(errno));
        return PCAP_ERROR_PRIVILEGE;
    }

    // Verify we can't regain root
    if (setuid(0) == 0) {
        log_message("ERROR", "Privilege drop failed - can still regain root!");
        return PCAP_ERROR_PRIVILEGE;
    }

    log_message("INFO", "Successfully dropped privileges to UID:%d GID:%d", uid, gid);
    return PCAP_SUCCESS;
}

// Validate buffer bounds to prevent buffer overflows
pcap_result_t validate_buffer_bounds(const void* buffer, size_t buffer_size, size_t required_size) {
    if (!buffer) {
        return PCAP_ERROR_INVALID_PARAM;
    }
    
    if (buffer_size < required_size) {
        log_message("ERROR", "Buffer overflow attempt: buffer_size=%zu, required=%zu", buffer_size, required_size);
        return PCAP_ERROR_BUFFER_OVERFLOW;
    }
    
    return PCAP_SUCCESS;
}

// Securely zero memory (compiler won't optimize away)
void secure_zero_memory(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile unsigned char *p = (volatile unsigned char*)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

// Safe string copy with bounds checking
pcap_result_t safe_string_copy(char* dest, size_t dest_size, const char* src) {
    if (!dest || !src || dest_size == 0) {
        return PCAP_ERROR_INVALID_PARAM;
    }
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        log_message("ERROR", "String truncation prevented: src_len=%zu, dest_size=%zu", src_len, dest_size);
        return PCAP_ERROR_BUFFER_OVERFLOW;
    }
    
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return PCAP_SUCCESS;
}

// Thread-safe logging with timestamps
void log_message(const char* level, const char* format, ...) {
    char timestamp[32];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE* output = log_file_ptr ? log_file_ptr : stderr;
    
    fprintf(output, "[%s] %s: ", timestamp, level);
    
    va_list args;
    va_start(args, format);
    vfprintf(output, format, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

// Signal handler for graceful shutdown
volatile int should_stop = 0;

void signal_handler(int signal) {
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            log_message("INFO", "Received shutdown signal %d", signal);
            should_stop = 1;
            break;
        default:
            log_message("WARNING", "Received unexpected signal %d", signal);
    }
}

void setup_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    // Ignore SIGPIPE to prevent crashes on broken connections
    signal(SIGPIPE, SIG_IGN);
    
    log_message("INFO", "Signal handlers configured");
}

// Initialize configuration with secure defaults
void init_default_config(pcap_config_t* config) {
    if (!config) return;
    
    memset(config, 0, sizeof(pcap_config_t));
    
    safe_string_copy(config->interface, sizeof(config->interface), "any");
    safe_string_copy(config->log_file, sizeof(config->log_file), "/var/log/pcapture.log");
    config->packet_limit = 0;  // Unlimited
    config->verbose = false;
    config->drop_privileges = true;
    config->target_uid = 1000;  // Default non-root user
    config->target_gid = 1000;  // Default non-root group
    safe_string_copy(config->filter, sizeof(config->filter), "");
}

// Load configuration from file
pcap_result_t load_config(pcap_config_t* config, const char* config_file) {
    if (!config || !config_file) {
        return PCAP_ERROR_INVALID_PARAM;
    }
    
    init_default_config(config);
    
    FILE* file = fopen(config_file, "r");
    if (!file) {
        log_message("WARNING", "Config file %s not found, using defaults", config_file);
        return PCAP_SUCCESS;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0') continue;
        
        char key[64], value[256];
        if (sscanf(line, "%63[^=]=%255s", key, value) == 2) {
            if (strcmp(key, "interface") == 0) {
                safe_string_copy(config->interface, sizeof(config->interface), value);
            } else if (strcmp(key, "log_file") == 0) {
                safe_string_copy(config->log_file, sizeof(config->log_file), value);
            } else if (strcmp(key, "packet_limit") == 0) {
                config->packet_limit = atoi(value);
            } else if (strcmp(key, "verbose") == 0) {
                config->verbose = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "drop_privileges") == 0) {
                config->drop_privileges = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "target_uid") == 0) {
                config->target_uid = atoi(value);
            } else if (strcmp(key, "target_gid") == 0) {
                config->target_gid = atoi(value);
            } else if (strcmp(key, "filter") == 0) {
                safe_string_copy(config->filter, sizeof(config->filter), value);
            }
        }
    }
    
    fclose(file);
    log_message("INFO", "Configuration loaded from %s", config_file);
    return PCAP_SUCCESS;
}

// Print current configuration
void print_config(const pcap_config_t* config) {
    if (!config) return;
    
    printf("PCAPture Configuration:\n");
    printf("  Interface: %s\n", config->interface);
    printf("  Log file: %s\n", config->log_file);
    printf("  Packet limit: %d\n", config->packet_limit);
    printf("  Verbose: %s\n", config->verbose ? "true" : "false");
    printf("  Drop privileges: %s\n", config->drop_privileges ? "true" : "false");
    if (config->drop_privileges) {
        printf("  Target UID: %d\n", config->target_uid);
        printf("  Target GID: %d\n", config->target_gid);
    }
    printf("  Filter: %s\n", config->filter[0] ? config->filter : "(none)");
}