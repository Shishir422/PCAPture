#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#include "parser.h"
#include "utils.h"

// Process a complete packet with security checks
pcap_result_t process_packet(const unsigned char* buffer, size_t size, const pcap_config_t* config) {
    if (!buffer || !config || size == 0) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    packet_info_t info;
    memset(&info, 0, sizeof(info));
    
    // Set timestamp
    clock_gettime(CLOCK_REALTIME, &info.timestamp);
    info.packet_size = size;
    
    pcap_result_t result = parse_ethernet_header(buffer, size, &info);
    if (result != PCAP_SUCCESS) {
        return result;
    }

    // Apply packet filter if specified
    if (config->filter[0] && !should_filter_packet(&info, config->filter)) {
        return PCAP_SUCCESS; // Filtered out, not an error
    }

    // Print packet information
    print_packet_info(&info, config->verbose);
    
    return PCAP_SUCCESS;
}

// Parse Ethernet header with bounds checking
pcap_result_t parse_ethernet_header(const unsigned char* buffer, size_t buffer_size, packet_info_t* info) {
    if (!buffer || !info) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    // Validate buffer has enough space for Ethernet header
    pcap_result_t result = validate_buffer_bounds(buffer, buffer_size, sizeof(struct ethhdr));
    if (result != PCAP_SUCCESS) {
        return result;
    }

    const struct ethhdr* eth = (const struct ethhdr*)buffer;
    
    // Store protocol information
    info->eth_protocol = ntohs(eth->h_proto);
    info->is_valid = true;

    // Parse IP layer if it's IPv4
    if (info->eth_protocol == ETH_P_IP) {
        return parse_ip_header(buffer, buffer_size, sizeof(struct ethhdr), info);
    }

    return PCAP_SUCCESS;
}

// Parse IP header with enhanced security
pcap_result_t parse_ip_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info) {
    if (!buffer || !info) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    // Validate buffer bounds for IP header
    pcap_result_t result = validate_buffer_bounds(buffer, buffer_size, offset + sizeof(struct iphdr));
    if (result != PCAP_SUCCESS) {
        return result;
    }

    const struct iphdr* ip = (const struct iphdr*)(buffer + offset);
    
    // Validate IP header length
    size_t ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr)) {
        log_message("WARNING", "Invalid IP header length: %zu", ip_header_len);
        return PCAP_ERROR_PARSE;
    }

    result = validate_buffer_bounds(buffer, buffer_size, offset + ip_header_len);
    if (result != PCAP_SUCCESS) {
        return result;
    }

    // Store IP information
    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->ip_protocol = ip->protocol;

    // Parse transport layer
    size_t transport_offset = offset + ip_header_len;
    
    switch (ip->protocol) {
        case IPPROTO_TCP:
            return parse_tcp_header(buffer, buffer_size, transport_offset, info);
        case IPPROTO_UDP:
            return parse_udp_header(buffer, buffer_size, transport_offset, info);
        case IPPROTO_ICMP:
            return parse_icmp_header(buffer, buffer_size, transport_offset, info);
        default:
            // Unknown protocol, but not an error
            break;
    }

    return PCAP_SUCCESS;
}

// Parse TCP header with bounds checking
pcap_result_t parse_tcp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info) {
    if (!buffer || !info) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    pcap_result_t result = validate_buffer_bounds(buffer, buffer_size, offset + sizeof(struct tcphdr));
    if (result != PCAP_SUCCESS) {
        return result;
    }

    const struct tcphdr* tcp = (const struct tcphdr*)(buffer + offset);
    
    info->src_port = ntohs(tcp->source);
    info->dst_port = ntohs(tcp->dest);

    return PCAP_SUCCESS;
}

// Parse UDP header with bounds checking
pcap_result_t parse_udp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info) {
    if (!buffer || !info) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    pcap_result_t result = validate_buffer_bounds(buffer, buffer_size, offset + sizeof(struct udphdr));
    if (result != PCAP_SUCCESS) {
        return result;
    }

    const struct udphdr* udp = (const struct udphdr*)(buffer + offset);
    
    info->src_port = ntohs(udp->source);
    info->dst_port = ntohs(udp->dest);

    return PCAP_SUCCESS;
}

// Parse ICMP header with bounds checking
pcap_result_t parse_icmp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info) {
    if (!buffer || !info) {
        return PCAP_ERROR_INVALID_PARAM;
    }

    pcap_result_t result = validate_buffer_bounds(buffer, buffer_size, offset + sizeof(struct icmphdr));
    if (result != PCAP_SUCCESS) {
        return result;
    }

    // ICMP doesn't have ports, set to 0
    info->src_port = 0;
    info->dst_port = 0;

    return PCAP_SUCCESS;
}

// Print packet information in a secure, formatted way
void print_packet_info(const packet_info_t* info, bool verbose) {
    if (!info || !info->is_valid) {
        return;
    }

    // Format timestamp
    char time_str[32];
    struct tm* tm_info = localtime(&info->timestamp.tv_sec);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    // Convert IP addresses to strings safely
    struct in_addr src_addr = { .s_addr = info->src_ip };
    struct in_addr dst_addr = { .s_addr = info->dst_ip };
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    if (!inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str))) {
        strcpy(src_ip_str, "unknown");
    }
    if (!inet_ntop(AF_INET, &dst_addr, dst_ip_str, sizeof(dst_ip_str))) {
        strcpy(dst_ip_str, "unknown");
    }

    // Print basic packet info
    printf("[%s.%03ld] ", time_str, info->timestamp.tv_nsec / 1000000);

    if (info->eth_protocol == ETH_P_IP) {
        const char* protocol_name = "Unknown";
        switch (info->ip_protocol) {
            case IPPROTO_TCP: protocol_name = "TCP"; break;
            case IPPROTO_UDP: protocol_name = "UDP"; break;
            case IPPROTO_ICMP: protocol_name = "ICMP"; break;
        }

        if (info->ip_protocol == IPPROTO_TCP || info->ip_protocol == IPPROTO_UDP) {
            printf("%s %s:%u -> %s:%u (%zu bytes)\n",
                   protocol_name, src_ip_str, info->src_port,
                   dst_ip_str, info->dst_port, info->packet_size);
        } else {
            printf("%s %s -> %s (%zu bytes)\n",
                   protocol_name, src_ip_str, dst_ip_str, info->packet_size);
        }
    } else {
        printf("Ethernet Protocol 0x%04X (%zu bytes)\n", info->eth_protocol, info->packet_size);
    }

    // Print detailed information in verbose mode
    if (verbose && info->eth_protocol == ETH_P_IP) {
        printf("  ├─ Source IP: %s\n", src_ip_str);
        printf("  ├─ Dest IP: %s\n", dst_ip_str);
        printf("  ├─ Protocol: %u\n", info->ip_protocol);
        
        if (info->src_port || info->dst_port) {
            printf("  ├─ Source Port: %u\n", info->src_port);
            printf("  └─ Dest Port: %u\n", info->dst_port);
        }
        printf("\n");
    }
}

// Simple packet filtering (can be extended with more sophisticated filters)
bool should_filter_packet(const packet_info_t* info, const char* filter) {
    if (!info || !filter || !filter[0]) {
        return true; // No filter, allow all
    }

    // Convert filter to lowercase for case-insensitive matching
    char filter_lower[256];
    size_t i;
    for (i = 0; i < sizeof(filter_lower) - 1 && filter[i]; i++) {
        filter_lower[i] = tolower(filter[i]);
    }
    filter_lower[i] = '\0';

    // Simple protocol filtering
    if (info->eth_protocol == ETH_P_IP) {
        switch (info->ip_protocol) {
            case IPPROTO_TCP:
                return strstr(filter_lower, "tcp") != NULL;
            case IPPROTO_UDP:
                return strstr(filter_lower, "udp") != NULL;
            case IPPROTO_ICMP:
                return strstr(filter_lower, "icmp") != NULL;
        }
    }

    // Port filtering (basic)
    if (info->src_port || info->dst_port) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", info->src_port);
        if (strstr(filter_lower, port_str)) return true;
        
        snprintf(port_str, sizeof(port_str), "%u", info->dst_port);
        if (strstr(filter_lower, port_str)) return true;
    }

    return false; // Filter didn't match
}