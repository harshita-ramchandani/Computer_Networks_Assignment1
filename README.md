# Computer_Networks_Assignment1
The Group members:
Harshita Ramchandani- 20110074
Ishani Chogle- 20110048

Please make sure to insatll the 'pcap' library installed in your system, by running the command:
$sudo apt-get install libpcap-dev

Part1 the code is to be complied with the command
$gcc -o part1 part1.c -lpcap

Where "part1" is the name of the excutable file to be made and "Part1.c" is the file name.
Please make sure you are inthe correct directory.
For Part1, (20110074+20110048)%3=1. Therefore, the refered file according to the instruction is 1.pcap.

Implimentation in brief:
Sockets are data units going through our network. Each of the sockets contain multiple packets which carry the data (videos, login credentials etc.).
Our job was to make a raw socket and capture the packets.

* The packet_handler function is called for each captured packet. It extracts and processes TCP packets.
* It begins by parsing the Ethernet II header (assuming Ethernet II) and moves to the IP header by skipping the Ethernet header.
* If the packet is a TCP packet (IP protocol number IPPROTO_TCP), it extracts relevant information like source IP, destination IP, source port, and destination port.
* It then prints the packet details, including the source and destination IPs, ports, and packet length. It also increments the count variable to keep track of the total number of packets processed.
* In the main function, the program expects the user to provide the path to a pcap file as a command-line argument (e.g., ./program_name pcap_file.pcap).
* It opens the specified pcap file using pcap_open_offline and handles any errors that may occur during file opening.
* It starts the packet capture loop using pcap_loop. The packet_handler function is called for each packet.
* After the capture loop completes, the program prints the total number of packets processed and closes the pcap file using pcap_close.

To run the program after compilation:
$./part1 <pcap_file>

Here, pass the path to the pcap file from which you want to sniff the packets from. (The packets are sniffed from the ongoing network but according the need of the question the packets are sniffed from the pcap file.)

Part2 

Part2 the code is to be complied with the command
$gcc -o part2 part2.c -lpcap

Where "part2" is the name of the excutable file to be made and "Part2.c" is the file name.
Please make sure you are inthe correct directory.
For Part1, (20110074+20110048)%4=2. Therefore, the refered file according to the instruction is 2.pcap.

Our list of questions to be answered:
1. There is a Flag in a TCP Packet. Identify the flag. (Hint: Search for the keyword Flag)
2. My username is secret, Identify my secret.
3. I have a TCP checksum “0x0ac4”. I have instructions in my path.
4. My device has an IP Address “131.144.126.118”. Sum of my connection ports will lead you to a person.
5. I come from localhost, I requested a milkshake. Find my flavour.

* For searching the keyword we give the program the keyword, the searchKeyword() function is used. 
* Packets with the following keywords are displayed the ones which meet the condition are taken into account.
* This is used in for question1 and question2 were answered this way by searching for the keywords "Flag" and "secret" respectively.
* The flag is Hamlet.
* The secret: I am batman.
* The checkTCPChecksum() function is used to evaluate tcp Checksum to find the packet with checksum “0x0ac4”. As asked in the question. Following up the instructions we get the Password-Denver.
* findPacketWithIPAddressAndPortSum(const unsigned char *packet, const struct pcap_pkthdr *pkthdr) this function looks for the specified IP Address, in our case “131.144.126.118”.
* The port sum we accquired we checked for the ports and a source port with equal value to the port sum led us to the person Oscar Wilde.
* We searched the keyword milshake and in the packet details (payload data) we found the flavour to be Banana.

To run the program after compilation:
$./part2 <pcap_file>

Here, pass the path to the pcap file from which you want to sniff the packets from.
