#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "capture.h"
#include "utils.h"

// Function prototypes
static void print_usage(const char* program_name);
static void print_version(void);
static pcap_result_t parse_arguments(int argc, char* argv[], pcap_config_t* config);

#define VERSION "2.0.0"

int main(int argc, char* argv[]) {
    pcap_config_t config;
    pcap_result_t result;

    // Initialize default configuration
    init_default_config(&config);

    // Parse command line arguments
    result = parse_arguments(argc, argv, &config);
    if (result != PCAP_SUCCESS) {
        return (result == PCAP_ERROR_INVALID_PARAM) ? 0 : 1; // Help/version shown
    }

    printf("PCAPture v%s - Enhanced Network Packet Sniffer\n", VERSION);
    printf("================================================\n\n");

    // Load configuration file if it exists
    load_config(&config, "/etc/pcapture.conf");
    
    // Check if running as root (required for raw sockets)
    if (getuid() != 0) {
        fprintf(stderr, "Error: PCAPture requires root privileges to create raw sockets.\n");
        fprintf(stderr, "Please run with: sudo %s\n", argv[0]);
        return 1;
    }

    // Drop privileges after socket creation if requested
    if (config.drop_privileges) {
        log_message("INFO", "Will drop privileges to UID:%d GID:%d after socket creation", 
                   config.target_uid, config.target_gid);
    }

    // Start packet capture
    printf("Starting packet capture on interface: %s\n", config.interface);
    if (config.packet_limit > 0) {
        printf("Capture limit: %d packets\n", config.packet_limit);
    }
    if (config.filter[0]) {
        printf("Filter: %s\n", config.filter);
    }
    printf("\nPress Ctrl+C to stop capture...\n\n");

    result = start_capture(&config);
    
    if (result != PCAP_SUCCESS) {
        fprintf(stderr, "Capture failed with error code: %d\n", result);
        return 1;
    }

    printf("PCAPture finished successfully.\n");
    return 0;
}

// Print program usage information
static void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Enhanced Network Packet Sniffer v%s\n\n", VERSION);
    printf("Options:\n");
    printf("  -i, --interface IFACE    Network interface to capture from (default: any)\n");
    printf("  -c, --count COUNT        Number of packets to capture (default: unlimited)\n");
    printf("  -f, --filter FILTER      Packet filter expression\n");
    printf("  -l, --log-file FILE      Log file path (default: /var/log/pcapture.log)\n");
    printf("  -v, --verbose            Enable verbose output\n");
    printf("  -n, --no-privileges      Don't drop privileges (stay as root)\n");
    printf("  -u, --uid UID            User ID to drop privileges to (default: 1000)\n");
    printf("  -g, --gid GID            Group ID to drop privileges to (default: 1000)\n");
    printf("  -h, --help               Show this help message\n");
    printf("  -V, --version            Show version information\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                       # Capture on any interface\n", program_name);
    printf("  %s -i eth0 -c 1000       # Capture 1000 packets on eth0\n", program_name);
    printf("  %s -f tcp -v             # Capture TCP packets with verbose output\n", program_name);
    printf("  %s -i wlan0 -f \"80\"      # Capture HTTP traffic on wlan0\n", program_name);
    printf("\n");
    printf("Security Features:\n");
    printf("  - Automatic privilege dropping after socket creation\n");
    printf("  - Buffer overflow protection with bounds checking\n");
    printf("  - Input validation and sanitization\n");
    printf("  - Secure memory handling and cleanup\n");
    printf("  - Signal handling for graceful shutdown\n");
    printf("\n");
}

// Print version information
static void print_version(void) {
    printf("PCAPture v%s\n", VERSION);
    printf("Enhanced Network Packet Sniffer with Security Features\n");
    printf("Built with security, reliability, and performance in mind.\n");
    printf("\nFeatures:\n");
    printf("  - Raw socket packet capture\n");
    printf("  - Ethernet, IP, TCP, UDP, ICMP parsing\n");
    printf("  - Privilege dropping for security\n");
    printf("  - Configurable packet filtering\n");
    printf("  - Comprehensive bounds checking\n");
    printf("  - Signal handling and graceful shutdown\n");
    printf("  - Detailed logging and statistics\n");
}

// Parse command line arguments
static pcap_result_t parse_arguments(int argc, char* argv[], pcap_config_t* config) {
    if (!config) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    static struct option long_options[] = {
        {"interface",     required_argument, 0, 'i'},
        {"count",         required_argument, 0, 'c'},
        {"filter",        required_argument, 0, 'f'},
        {"log-file",      required_argument, 0, 'l'},
        {"verbose",       no_argument,       0, 'v'},
        {"no-privileges", no_argument,       0, 'n'},
        {"uid",           required_argument, 0, 'u'},
        {"gid",           required_argument, 0, 'g'},
        {"help",          no_argument,       0, 'h'},
        {"version",       no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "i:c:f:l:vnu:g:hV", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                if (safe_string_copy(config->interface, sizeof(config->interface), optarg) != PCAP_SUCCESS) {
                    fprintf(stderr, "Error: Interface name too long\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'c':
                config->packet_limit = atoi(optarg);
                if (config->packet_limit < 0) {
                    fprintf(stderr, "Error: Packet count must be non-negative\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'f':
                if (safe_string_copy(config->filter, sizeof(config->filter), optarg) != PCAP_SUCCESS) {
                    fprintf(stderr, "Error: Filter expression too long\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'l':
                if (safe_string_copy(config->log_file, sizeof(config->log_file), optarg) != PCAP_SUCCESS) {
                    fprintf(stderr, "Error: Log file path too long\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'v':
                config->verbose = true;
                break;
                
            case 'n':
                config->drop_privileges = false;
                break;
                
            case 'u':
                config->target_uid = atoi(optarg);
                if (config->target_uid < 0) {
                    fprintf(stderr, "Error: UID must be non-negative\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'g':
                config->target_gid = atoi(optarg);
                if (config->target_gid < 0) {
                    fprintf(stderr, "Error: GID must be non-negative\n");
                    return PCAP_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'h':
                print_usage(argv[0]);
                return PCAP_ERROR_INVALID_PARAM; // Not really an error, just exit
                
            case 'V':
                print_version();
                return PCAP_ERROR_INVALID_PARAM; // Not really an error, just exit
                
            case '?':
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return PCAP_ERROR_INVALID_PARAM;
                
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                return PCAP_ERROR_INVALID_PARAM;
        }
    }

    // Check for extra arguments
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected arguments: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        return PCAP_ERROR_INVALID_PARAM;
    }

    return PCAP_SUCCESS;
}