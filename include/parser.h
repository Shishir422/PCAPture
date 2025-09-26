#ifndef PARSER_H
#define PARSER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

// Prototypes for packet parsing
void parse_ethernet_header(const unsigned char* buffer, int size);
void parse_ip_header(const unsigned char* buffer, int size);

#endif