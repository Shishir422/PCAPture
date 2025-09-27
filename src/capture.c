#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>

#include "capture.h"
#include "parser.h"
#include "utils.h"

// Global variables for signal handling
volatile int should_stop = 0;
static capture_stats_t global_stats;

// Signal handler for graceful shutdown
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

// Initialize packet capture with enhanced security
pcap_result_t init_capture(const pcap_config_t* config, int* sock_fd) {
    if (!config || !sock_fd) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    // Create raw socket with error checking
    *sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*sock_fd < 0) {
        log_message("ERROR", "Failed to create raw socket: %s", strerror(errno));
        
        // Provide helpful error message for common cases
        if (errno == EPERM || errno == EACCES) {
            log_message("ERROR", "Raw socket requires root privileges. Run with sudo or set CAP_NET_RAW capability.");
        }
        return PCAP_ERROR_SOCKET;
    }

    // Set socket timeout to allow periodic checks of should_stop
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1 second timeout
    timeout.tv_usec = 0;
    
    if (setsockopt(*sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message("WARNING", "Failed to set socket timeout: %s", strerror(errno));
    }

    // If specific interface is requested, bind to it
    if (strcmp(config->interface, "any") != 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        safe_string_copy(ifr.ifr_name, IFNAMSIZ, config->interface);
        
        if (ioctl(*sock_fd, SIOCGIFINDEX, &ifr) < 0) {
            log_message("ERROR", "Interface %s not found: %s", config->interface, strerror(errno));
            close(*sock_fd);
            return PCAP_ERROR_SOCKET;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(*sock_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            log_message("ERROR", "Failed to bind to interface %s: %s", config->interface, strerror(errno));
            close(*sock_fd);
            return PCAP_ERROR_SOCKET;
        }
        
        log_message("INFO", "Bound to interface: %s", config->interface);
    }

    log_message("INFO", "Raw socket initialized successfully");
    return PCAP_SUCCESS;
}

// Enhanced packet capture with security and error handling
pcap_result_t start_capture(const pcap_config_t* config) {
    if (!config) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    int sock_fd = -1;
    unsigned char* buffer = NULL;
    pcap_result_t result = PCAP_SUCCESS;
    
    // Initialize statistics
    memset(&global_stats, 0, sizeof(global_stats));
    global_stats.start_time = time(NULL);

    // Setup signal handlers for graceful shutdown
    setup_signal_handlers();

    // Initialize capture socket
    result = init_capture(config, &sock_fd);
    if (result != PCAP_SUCCESS) {
        return result;
    }

    // Allocate secure buffer with bounds checking
    buffer = calloc(1, MAX_PACKET_SIZE);
    if (!buffer) {
        log_message("ERROR", "Failed to allocate packet buffer: %s", strerror(errno));
        close(sock_fd);
        return PCAP_ERROR_MEMORY;
    }

    log_message("INFO", "PCAPture started - listening for packets on %s", config->interface);
    
    if (config->verbose) {
        print_config(config);
    }

    // Main capture loop with enhanced error handling
    struct sockaddr_ll saddr;
    socklen_t saddr_size = sizeof(saddr);
    
    while (!should_stop) {
        // Check packet limit
        if (config->packet_limit > 0 && global_stats.packets_captured >= (unsigned long)config->packet_limit) {
            log_message("INFO", "Packet limit reached: %lu", global_stats.packets_captured);
            break;
        }

        // Receive packet with timeout handling
        ssize_t data_size = recvfrom(sock_fd, buffer, MAX_PACKET_SIZE, 0, 
                                   (struct sockaddr*)&saddr, &saddr_size);
        
        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout occurred, continue loop to check should_stop
                continue;
            } else if (errno == EINTR) {
                // Interrupted by signal, check should_stop
                continue;
            } else {
                log_message("ERROR", "Error receiving packet: %s", strerror(errno));
                global_stats.packets_dropped++;
                continue;
            }
        }

        if (data_size == 0) {
            // EOF or no more data
            continue;
        }

        // Validate packet size
        if (data_size > MAX_PACKET_SIZE) {
            log_message("WARNING", "Packet size %zd exceeds maximum %d, dropping", 
                       data_size, MAX_PACKET_SIZE);
            global_stats.packets_dropped++;
            continue;
        }

        // Process packet with bounds checking
        result = process_packet(buffer, (size_t)data_size, config);
        if (result == PCAP_SUCCESS) {
            global_stats.packets_captured++;
            global_stats.bytes_captured += (unsigned long)data_size;
        } else {
            global_stats.packets_dropped++;
        }

        // Periodic statistics reporting (every 1000 packets)
        if (config->verbose && global_stats.packets_captured % 1000 == 0) {
            print_capture_stats(&global_stats);
        }
    }

    // Cleanup and final statistics
    log_message("INFO", "Capture stopped");
    print_capture_stats(&global_stats);
    
    cleanup_capture(sock_fd, buffer);
    return PCAP_SUCCESS;
}

// Clean up resources
pcap_result_t cleanup_capture(int sock_fd, unsigned char* buffer) {
    if (sock_fd >= 0) {
        close(sock_fd);
        log_message("INFO", "Socket closed");
    }
    
    if (buffer) {
        secure_zero_memory(buffer, MAX_PACKET_SIZE);
        free(buffer);
        log_message("INFO", "Buffer cleaned and freed");
    }
    
    return PCAP_SUCCESS;
}

// Print capture statistics
void print_capture_stats(const capture_stats_t* stats) {
    if (!stats) return;
    
    time_t now = time(NULL);
    double elapsed = difftime(now, stats->start_time);
    double rate = elapsed > 0 ? (double)stats->packets_captured / elapsed : 0.0;
    
    printf("\n=== Capture Statistics ===\n");
    printf("Packets captured: %lu\n", stats->packets_captured);
    printf("Packets dropped:  %lu\n", stats->packets_dropped);
    printf("Bytes captured:   %lu\n", stats->bytes_captured);
    printf("Elapsed time:     %.1f seconds\n", elapsed);
    printf("Capture rate:     %.2f packets/sec\n", rate);
    printf("========================\n\n");
}