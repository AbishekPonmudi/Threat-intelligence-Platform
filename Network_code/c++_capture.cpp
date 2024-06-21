// Including necessary libraries
#include<iostream>  // Standard Input / Output Streams Library
#include<pcap.h>    // PCAP library for capturing network traffic
#include<stdlib.h>  // Standard General Utilities Library
#include<netinet/ip.h> // Provides declarations for IP header

using namespace std; // Allows use of std namespace items without prefixing with std::

// Prototype for the packet processing function.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Main function
int main() {
    // Define a PCAP descriptor for the capture source
    pcap_t *descr;

    // Define an error buffer to store error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the WiFi interface for live capture
    descr = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    // If there was an error opening the interface, descr will be NULL
    if (descr == NULL) {
        // Print an error message and exit with an error code
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // Process the packets from the capture source. For each packet, it will call the packetHandler function
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        // If there was an error processing the packets, print an error message and exit with an error code
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    // Print a message indicating that the capture is finished
    cout << "capture finished." << endl;

    // Exit with a success code
    return 0;
}

// This function will be called for each packet that is processed
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Define a pointer to an IP header structure, we assume ethernet frame here so we skip first 14 bytes
    struct ip* ip_header = (struct ip*)(packet + 14);

    // Print the source and destination IP addresses from the IP header
    cout << "From: " << inet_ntoa(ip_header->ip_src) << endl;
    cout << "To: " << inet_ntoa(ip_header->ip_dst) << endl;
}