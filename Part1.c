//(20110074+20110048)%3=1

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

typedef struct {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
} Flow;
int count=0;
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet II header

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        Flow flow;
        flow.src_ip = ip_header->ip_src;
        flow.dest_ip = ip_header->ip_dst;
        flow.src_port = ntohs(tcp_header->th_sport);
        flow.dest_port = ntohs(tcp_header->th_dport);

        printf("Packet captured. Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
            inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
            count++;

        // Add your packet processing logic here for different flows
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);

    if (pcap == NULL) {
        printf("Error opening pcap file: %s\n", errbuf);
        exit(1);
    }

    printf("Sniffing packets from %s...\n", argv[1]);

    if (pcap_loop(pcap, 0, packet_handler, NULL) < 0) {
        printf("Error in pcap_loop: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        exit(1);
    }
    printf("total packets: %d", count);
    pcap_close(pcap);

    return 0;
}


    close(raw_socket);
    return 0;
}
