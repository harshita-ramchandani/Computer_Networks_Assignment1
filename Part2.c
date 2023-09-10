//(20110074+20110048)%4=2

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h> // Added for string functions
#include <ctype.h> // Added for case-insensitive search

typedef struct {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
} Flow;

int count = 0;
int checksumMatch = 0;

// Function to search for the keyword "Flag" in packet payload (case-insensitive)
int searchKeyword(const unsigned char *payload, int payload_len) {
    const char *keyword = "10937"; // Case-insensitive search
    const unsigned char *ptr = payload;

    // Loop through the payload to search for the keyword (case-insensitive)
    while (ptr + strlen(keyword) <= payload + payload_len) {
        if (strncasecmp((const char *)ptr, keyword, strlen(keyword)) == 0) {
            // Keyword found, return the position
            return ptr - payload;
        }
        ptr++;
    }

    // Keyword not found
    return -1;
}

// Function to search for the username "secret" in packet payload (case-insensitive)
int searchUsername(const unsigned char *payload, int payload_len, const char *username) {
    const char *ptr = (const char *)payload;

    // Loop through the payload to search for the username (case-insensitive)
    while (ptr + strlen(username) <= (const char *)payload + payload_len) {
        if (strncasecmp(ptr, username, strlen(username)) == 0) {
            // Username found, return the position
            return ptr - (const char *)payload;
        }
        ptr++;
    }

    // Username not found
    return -1;
}

// Function to check if a packet has a specific TCP checksum
int checkTCPChecksum(const unsigned char *packet, int checksum) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet II header
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));

        // Extract TCP checksum from the packet header
        int tcp_checksum = ntohs(tcp_header->th_sum);

        if (tcp_checksum == checksum) {
            return 1; // TCP checksum matches
        }
    }
    return 0; // TCP checksum doesn't match
}

// Function to print packet details containing the keyword "password" in the stream
int searchPassword(const unsigned char *payload, int payload_len) {
    const char *keyword = "PASSWORD";
    const unsigned char *ptr = payload;

    // Loop through the payload to search for the keyword "password" (case-insensitive)
    while (ptr + strlen(keyword) <= payload + payload_len) {
        if (strncasecmp((const char *)ptr, keyword, strlen(keyword)) == 0) {
            // Keyword found, return the position
            return ptr - payload;
        }
        ptr++;
    }

    // Keyword not found
    return -1;
}

void findPacketWithIPAddressAndPortSum(const unsigned char *packet, const struct pcap_pkthdr *pkthdr) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet II header
    Flow flow;
    flow.src_ip = ip_header->ip_src;
    flow.dest_ip = ip_header->ip_dst;

    // Check if the current packet has the desired IP address
    if (strcmp(inet_ntoa(flow.src_ip), "131.144.126.118") == 0 || strcmp(inet_ntoa(flow.dest_ip), "131.144.126.118") == 0) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        flow.src_port = ntohs(tcp_header->th_sport);
        flow.dest_port = ntohs(tcp_header->th_dport);

        // Calculate the sum of source and destination ports
        int port_sum = flow.src_port + flow.dest_port;

        printf("Packet Details (IP Address and Port Sum):\n");
        printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
               inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
        printf("Sum of Source and Destination Ports: %d\n", port_sum);
    }
}

// Function to find packets with the specified sum of source and destination ports
int findPacketWithPortSum(Flow flow, const unsigned char *payload, int payload_len) {
    int sum = flow.src_port + flow.dest_port;
    char keyword[16];  // Assuming the maximum length of the keyword is 15 characters
    snprintf(keyword, sizeof(keyword), "%d", sum);

    const unsigned char *ptr = payload;

    // Loop through the payload to search for the keyword (case-insensitive)
    while (ptr + strlen(keyword) <= payload + payload_len) {
        if (strncasecmp((const char *)ptr, keyword, strlen(keyword)) == 0) {
            // Keyword found, return the position
            return ptr - payload;
        }
        ptr++;
    }

    // Keyword not found
    return -1;
}

int searchForPerson(const unsigned char *payload, int payload_len) {
    
    const char *person_identifier = "10937"; // Modify to match the actual person identifier
    const unsigned char *ptr = payload;

    while (ptr + strlen(person_identifier) <= payload + payload_len) {
        if (memcmp(ptr, person_identifier, strlen(person_identifier)) == 0) {
            // Person found, return the position or perform further actions
            return ptr - payload;
        }
        ptr++;
    }

    // Person not found
    return -1;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet II header

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        Flow flow;
        flow.src_ip = ip_header->ip_src;
        flow.dest_ip = ip_header->ip_dst;
        flow.src_port = ntohs(tcp_header->th_sport);
        flow.dest_port = ntohs(tcp_header->th_dport);

        // Extract the TCP payload
        int payload_offset = 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
        int payload_len = pkthdr->len - payload_offset;
        const unsigned char *payload = packet + payload_offset;

        // Search for the keyword "Flag" (case-insensitive) in the payload
        /*int keyword_pos = searchKeyword(payload, payload_len);
        if (keyword_pos != -1) {
            // Print the entire packet details
            printf("Packet Details:\n");
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                   inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);

            printf("Payload Data:\n");
            // Print the payload data from keyword_pos to the end of the statement
            for (int i = 0; i < payload_len; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        }
        
        /*int username_pos = searchUsername(payload, payload_len, "secret");
        if (username_pos != -1) {
            // Print the entire packet details
            printf("Packet Details (Username):\n");
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                   inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);

            printf("Payload Data (Username):\n");
            // Print the payload data from username_pos to the end of the statement
            for (int i = 0; i < payload_len; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        }*/
        
        /*int tcpChecksum = 0x0ac4;
        if (checkTCPChecksum(packet, tcpChecksum)) {
            // Print the entire packet details
            printf("Packet Details (TCP Checksum):\n");
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                   inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
            
            printf("Payload Data :\n");
            // Print the payload data from keyword_pos to the end of the statement
            for (int i = 0; i < payload_len; i++) {
                printf("%c", payload[i]);
            }
            
        }
        if (checkTCPChecksum(packet, 0x0ac4)) {
            checksumMatch = 1; // Set the flag to indicate checksum match
        }

        // If checksum condition is satisfied, search for "password" in payload
        if (checksumMatch) {
            int password_pos = searchPassword(payload, payload_len);
            if (password_pos != -1) {
                printf("Packet Details (Password):\n");
                printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                    inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
                printf("Payload Data (Password):\n");

                // Print the payload data from password_pos to the end of the statement
                for (int i = password_pos; i < payload_len; i++) {
                    printf("%c", payload[i]);
                }
                printf("\n");
                // Reset the flag after processing the packet
                checksumMatch = 0;
            }
        }
        
        int port_sum=0;
	// Check for the packet with the specific IP address and calculate the sum of its connection ports
        if (strcmp(inet_ntoa(flow.src_ip), "131.144.126.118") == 0 || strcmp(inet_ntoa(flow.dest_ip), "131.144.126.118") == 0) {
            int port_sum = flow.src_port + flow.dest_port;
            printf("Packet Details (IP Address and Port Sum):\n");
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
            printf("Sum of Source and Destination Ports: %d\n", port_sum);
            
        }*/
        // Assuming you have identified the packet with IP address and calculated port_sum
	/*int person_info_pos = searchForPerson(payload, payload_len);

	    if (person_info_pos != -1) {
		printf("Packet Details (Person):\n");
		printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
		    inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);
		printf("Sum of Source and Destination Ports: %d\n", port_sum);

		// Print the person-specific information found in the payload
		printf("Person's Information:\n");
		for (int i = person_info_pos; i < payload_len; i++) {
		    printf("%c", payload[i]);
		}
		printf("\n");
	    }*/
	    
	    int desired_port = 10937; // Change this to your desired source port
        if (flow.src_port == desired_port) {
            printf("Packet Details (Source Port %d):\n", desired_port);
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Length: %d\n",
                inet_ntoa(flow.src_ip), flow.src_port, inet_ntoa(flow.dest_ip), flow.dest_port, pkthdr->len);

            // Print the packet payload data
            printf("Payload Data:\n");
            for (int i = 0; i < payload_len; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        }

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
    printf("Total packets: %d\n", count);
    pcap_close(pcap);

    return 0;
}
