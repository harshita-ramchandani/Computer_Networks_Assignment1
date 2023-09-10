#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int raw_socket;
    char packet_buffer[65536];
    socklen_t socklen;
    int data_size;
    int packet_count = 0;
    int client_port = 0;
    int server_port = 0;

    // Create a raw socket to capture all Ethernet frames
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    while (1) {
        socklen = sizeof(struct sockaddr);

        // Receive a packet
        data_size = recvfrom(raw_socket, packet_buffer, sizeof(packet_buffer), 0, NULL, &socklen);
        if (data_size < 0) {
            perror("Packet capture error");
            close(raw_socket);
            exit(1);
        }

        // Parse the Ethernet header
        struct ethhdr* eth_header = (struct ethhdr*)packet_buffer;

        // Check if the packet contains an IP header
        if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            // Parse the IP header
            struct ip* ip_header = (struct ip*)(packet_buffer + sizeof(struct ethhdr));

            // Check if the packet contains TCP or UDP data
            if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
                // Parse the transport layer header
                void* transport_header = (packet_buffer + sizeof(struct ethhdr) + (ip_header->ip_hl << 2));

                // Extract source and destination IP addresses and ports
                char source_ip[INET_ADDRSTRLEN];
                char dest_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

                // Check if it's TCP or UDP and extract port numbers accordingly
                if (ip_header->ip_p == IPPROTO_TCP) {
                    struct tcphdr* tcp_header = (struct tcphdr*)transport_header;
                    uint16_t source_port = ntohs(tcp_header->th_sport);
                    uint16_t dest_port = ntohs(tcp_header->th_dport);

                    // Update counters
                    client_port = source_port;
                    server_port = dest_port;

                    // Print the information for the TCP flow
                    printf("Client IP: %s:%d\n", source_ip, source_port);
                    printf("Server IP: %s:%d\n", dest_ip, dest_port);
                } else if (ip_header->ip_p == IPPROTO_UDP) {
                    struct udphdr* udp_header = (struct udphdr*)transport_header;
                    uint16_t source_port = ntohs(udp_header->uh_sport);
                    uint16_t dest_port = ntohs(udp_header->uh_dport);

                    // Update counters
                    client_port = source_port;
                    server_port = dest_port;

                    // Print the information for the UDP flow
                    printf("Client IP: %s:%d\n", source_ip, source_port);
                    printf("Server IP: %s:%d\n", dest_ip, dest_port);
                }

                // Increment the packet count
                packet_count++;
            }
        }

        // Print the number of packets captured
        printf("Packets Captured: %d\n", packet_count);
    }

    close(raw_socket);
    return 0;
}
