#ifndef PARSER_H
#define PARSER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "utils.h"

// Packet information structure
typedef struct {
    struct timespec timestamp;
    size_t packet_size;
    uint16_t eth_protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_protocol;
    bool is_valid;
} packet_info_t;

// Enhanced parsing functions with bounds checking
pcap_result_t parse_ethernet_header(const unsigned char* buffer, size_t buffer_size, packet_info_t* info);
pcap_result_t parse_ip_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info);
pcap_result_t parse_tcp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info);
pcap_result_t parse_udp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info);
pcap_result_t parse_icmp_header(const unsigned char* buffer, size_t buffer_size, size_t offset, packet_info_t* info);

// Packet processing
pcap_result_t process_packet(const unsigned char* buffer, size_t size, const pcap_config_t* config);
void print_packet_info(const packet_info_t* info, bool verbose);
bool should_filter_packet(const packet_info_t* info, const char* filter);

#endif