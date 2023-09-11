#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <time.h>

void processPacket(unsigned char* packetData, int packetSize);
int extractPidFromSsOutput(const char* ssOutput);

int main() {
    int rawSocket;
    int socketAddressSize;
    struct sockaddr socketAddress;
    unsigned char *packetBuffer = (unsigned char *)malloc(65536);
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // Create a raw packet capture socket
    if (rawSocket < 0) {
        perror("Socket Error");
        return 1;
    }
    time_t startTime = time(NULL);
    while (difftime(time(NULL), startTime) < 30) {
        socketAddressSize = sizeof socketAddress;
        int dataSize = recvfrom(rawSocket, packetBuffer, 65536, 0, &socketAddress, (socklen_t*)&socketAddressSize); // Receive packets
        if (dataSize < 0) {
            perror("Recvfrom Error");
            return 1;
        }
        processPacket(packetBuffer, dataSize); // Process packets
    }
    close(rawSocket);
    free(packetBuffer);
    
    while (1) {
        printf("\nEnter port number: ");
        int portNumber;
        scanf("%d", &portNumber);
        char ssCommand[100];
        sprintf(ssCommand, "ss -tp sport = :%d | grep -Po 'pid=\\K\\d+'", portNumber);
        
        printf("\n");
        fflush(stdout);
        
        // Execute the command and capture its output
        FILE *ssProcess = popen(ssCommand, "r");
        if (ssProcess == NULL) {
            perror("popen error");
            continue;
        }
        
        char ssOutput[16]; // Assuming PID won't be longer than 16 characters
        if (fgets(ssOutput, sizeof(ssOutput), ssProcess) != NULL) {
            int pid = atoi(ssOutput);
            printf("Port %d is associated with Process ID: %d\n", portNumber, pid);
        } else {
            printf("No process found for Port %d\n", portNumber);
        }
        
        pclose(ssProcess);
    }
    return 0;
}

void processPacket(unsigned char* packetData, int packetSize) {
    struct ip *ipHeader = (struct ip *)(packetData + 14);
    struct tcphdr *tcpHeader = (struct tcphdr *)(packetData + 14 + ipHeader->ip_hl * 4); // Calculate TCP header location
    if (ipHeader->ip_p == IPPROTO_TCP) {
        printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
        printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
        printf("Destination Port: %d\n", ntohs(tcpHeader->th_dport));
        printf("--------------------\n");
    }
}
