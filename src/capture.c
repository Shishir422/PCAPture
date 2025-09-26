#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "parser.h"

// Function to start capturing packets
void start_capture() {
    int raw_sock;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(65536); // storage for packet
    socklen_t saddr_size;

    // Create raw socket: AF_PACKET = capture Ethernet frames, SOCK_RAW = raw access
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("Socket Error");
        return;
    }

    printf("Sniffer started... Listening for packets.\n");

    // Infinite loop to keep reading packets
    while (1) {
        saddr_size = sizeof(saddr);

        // recvfrom() copies the packet into our buffer
        int data_size = recvfrom(raw_sock, buffer, 65536, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }

        // Parse packet (Ethernet -> IP -> TCP/UDP/ICMP)
        parse_ethernet_header(buffer, data_size);
    }

    // Cleanup
    close(raw_sock);
    free(buffer);
}