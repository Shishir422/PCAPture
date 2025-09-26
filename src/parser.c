#include <stdio.h>
#include <arpa/inet.h>
#include "parser.h"

// Parse the Ethernet header of the packet
void parse_ethernet_header(const unsigned char* buffer, int size) {
    struct ethhdr *eth = (struct ethhdr *)buffer;

    printf("\nEthernet Header\n");
    printf("   |-Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X \n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Protocol        : %u \n", (unsigned short)eth->h_proto);

    // If it's an IPv4 packet, parse IP header next
    if (ntohs(eth->h_proto) == 0x0800) {
        parse_ip_header(buffer, size);
    }
}

// Parse IP + transport-layer (TCP/UDP/ICMP) headers
void parse_ip_header(const unsigned char* buffer, int size) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in src_addr, dest_addr;

    src_addr.sin_addr.s_addr = ip->saddr;
    dest_addr.sin_addr.s_addr = ip->daddr;

    printf("\nIP Header\n");
    printf("   |-Source IP        : %s\n", inet_ntoa(src_addr.sin_addr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(dest_addr.sin_addr));
    printf("   |-Protocol         : %d\n", (unsigned int)ip->protocol);

    // TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp =
            (struct tcphdr *)(buffer + ip->ihl*4 + sizeof(struct ethhdr));
        printf("\nTCP Header\n");
        printf("   |-Source Port      : %u\n", ntohs(tcp->source));
        printf("   |-Destination Port : %u\n", ntohs(tcp->dest));

    // UDP
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp =
            (struct udphdr *)(buffer + ip->ihl*4 + sizeof(struct ethhdr));
        printf("\nUDP Header\n");
        printf("   |-Source Port      : %u\n", ntohs(udp->source));
        printf("   |-Destination Port : %u\n", ntohs(udp->dest));

    // ICMP
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp =
            (struct icmphdr *)(buffer + ip->ihl*4 + sizeof(struct ethhdr));
        printf("\nICMP Header\n");
        printf("   |-Type : %d\n", icmp->type);
    }
}