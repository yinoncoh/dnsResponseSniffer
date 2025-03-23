#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>


#define DNS_PORT 53
#define MAX_FQDN_SIZE 253

#pragma pack(1)
// DNS header structure
struct dnsHdr {
    unsigned short id;            // Identification
    unsigned short flags;         // Flags
    unsigned short questions;     // Number of Questions
    unsigned short answers;       // Number of Answers
    unsigned short authority;     // Number of Authority
    unsigned short additional;    // Number of Additional
};
// DNS Question structure
struct dnsQuestion {
    // name - structured by a size and data
    unsigned short type;
    unsigned short class;
};
// DNS Answer structure
struct dnsAnswer {
    // name - can be 2 bytes field for a "pointer" or full dns name. Size is calculated by get_answer_name_size
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short length;
    // data - size and content is based om the type
};
#pragma pack()

// Function for extracting the domain name from a Question section 
// In addition it calculates the size used for storing it (so we can skip it for getting next fields)
// every part of the name has its own size in the first byte and at the end there is additional field for the 0.
int get_domain_name(const unsigned char *question, unsigned char *domain_name, int *domain_name_size) {
    int j = 0;
    int i = 0;
    domain_name[0]=0;

    while (question[i] != 0) {
        int length = question[i];
        if (j + length >= *domain_name_size) { // Not enough buffer space
            return 0;
        }
        i++;
        for (int k = 0; k < length; k++) {
            domain_name[j++] = question[i++];
        }
        domain_name[j++] = '.';
    }
    domain_name[j - 1] = '\0';  // Remove the last dot
    *domain_name_size = i + 1;     // Move the offset past the null byte

    return *domain_name_size;
}

// Function for calculating the name size in the Answer section
int get_answer_name_size(const unsigned char* name) {
    // If the first byte has the 2 most significant bits set (0xC0), it's a pointer
    if ((name[0] & 0xC0) == 0xC0) {
        // If it's a pointer, return 2 (size of pointer)
        return 2;
    } else {
        // Otherwise, it's a fully qualified domain name (FQDN)
        int length = 0;
        int i = 0;
        
        // Read the labels of the domain name
        while (name[i] != 0x00) {
            length += name[i] + 1; // Add the length of the label + 1 for the label's length byte
            i += name[i] + 1; // Move to the next label
        }
        // Add 1 byte for the terminating null byte
        length += 1;
        return length;
    }
}


// Take the IPv6 address and print it in Zero Compressed mode (the common usage)
void printZeroCompressedIPv6(unsigned char* data)
{
    // The RData field for an AAAA record is 16 bytes long (IPv6 address)
    uint16_t ipv6[8];  // Store the 8 blocks of the IPv6 address

    // Read the 16 bytes and convert them to 8 16-bit blocks
    for (int i = 0; i < 8; i++) {
        ipv6[i] = (data[2 * i] << 8) | data[2 * i + 1];
    }

    int first_non_zero = -1;  // Track the first non-zero block
    int zero_block_start = -1;  // Start of zero blocks
    int zero_block_count = 0;  // Count consecutive zero blocks

    // Find the longest sequence of zero blocks
    for (int i = 0; i < 8; i++) {
        if (ipv6[i] == 0) {
            if (zero_block_start == -1) {
                zero_block_start = i;  // Start of zero blocks
            }
            zero_block_count++;
        } else {
            if (zero_block_start != -1) {
                // If we encounter a non-zero block after zero blocks, stop
                break;
            }
            first_non_zero = i;  // Track the first non-zero block
        }
    }

    // Print the IPv6 address with zero compression
    int printed_blocks = 0;
    for (int i = 0; i < 8; i++) {
        // If we are at the start of a zero block sequence, print "::" once
        if (zero_block_count > 0 && i == zero_block_start) {
            printf("::");
            printed_blocks++;
            i += zero_block_count - 1;  // Skip all zero blocks
            continue;
        }

        // Print each block with leading zeros removed
        if (ipv6[i] != 0 || first_non_zero == i) {
            // Print a colon before each block (except for the first block)
            if (printed_blocks > 0) {
                printf(":");
            }

            // Print the current block
            printf("%x", ipv6[i]);
            printed_blocks++;
        }
    }
    printf("\n");    
}


// Parse the answers section
void parse_and_print_answers(unsigned short answers, const unsigned char *packet, int offset) {
    unsigned char *ip_address;
    for (int i = 0; i < ntohs(answers); i++) {
        // Skip the name field (variable length)
        offset += get_answer_name_size(packet + offset);
        // get the answer header
        struct dnsAnswer* answer = (struct dnsAnswer*)(packet + offset);
        // skip the rest answer header for getting the data
        offset += sizeof(struct dnsAnswer);
        ip_address = (unsigned char*)(packet + offset);

        if (ntohs(answer->type) == 1) { // A record (IPv4 address)
            printf("\tIPv4 Address: %d.%d.%d.%d\n", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
        }
        else if (ntohs(answer->type) == 28) { // AAAA record (IPv6 address)
            printf("\tIPv6 Address: ");
            printZeroCompressedIPv6(ip_address);
        }
        else if (ntohs(answer->type) == 5) { // CNAME record
            printf("\tCNAME\n");
            // Do nothing, no need to print it
        }
        else {
            //Unhandled type. Ignoring
        }
        offset += ntohs(answer->length);  // Move past the IP address
    }
    printf("\n");
}

// Function to parse the DNS response
void parse_dns_response(const unsigned char *packet) {
    struct dnsHdr *dns = (struct dnsHdr *)packet;
    char domain_name[MAX_FQDN_SIZE];
    int offset = 0;
    
    // Make sure it's indeed a DNS response
    if ((ntohs(dns->flags) & 0x8000) == 0) {
        return;
    }

    if(!dns->questions || !dns->answers) {
        //Questions or Answers are missing in this packet
        return;
    }

    // Get the domain name and skip the question section (we assume there's only one question)
    offset += sizeof(struct dnsHdr);
    int domain_name_size = sizeof(domain_name);
    if ( !get_domain_name(packet+offset, domain_name, &domain_name_size) ) {
        // Ignore this message
        return;
    }
    printf("Domain: %s\n", domain_name);
    // Skip the full question header
    offset += domain_name_size + sizeof(struct dnsQuestion);

    parse_and_print_answers(dns->answers, packet, offset);
}


// Callback function for pcap_loop
// Make sure that indeed a valid packet was uploaded by BPF filter
// (Valid UDP packet with source port of 53)
// If so, parse the packet
void packet_parser(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {

    if (pkthdr->len < sizeof(struct ether_header)) {
        fprintf(stderr, "Defevtive packet\n");
        return;
    }
    // Ethernet header
    struct ether_header *e_hdr =  (struct ether_header *)packet;
    if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "This packet is not an ETHERTYPE_IP packet (0x%04x)\n", ntohs(e_hdr->ether_type));
        return;
    }
    // IP header
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));  // Skip Ethernet header (14)
    if (ip_hdr->protocol != 17) {
        printf("This packet is not UDP\n");
        return;
    }
    // UDP header
    unsigned short iphdrlen;
    iphdrlen = ip_hdr->ihl*4;

    struct udphdr *udp_header = (struct udphdr *)(packet+sizeof(struct ether_header)+iphdrlen);  // Skip IP header
    // Check if it's a DNS response packet (UDP source port 53)
    if (ntohs(udp_header->source) == DNS_PORT) {
        parse_dns_response(packet + sizeof(struct ether_header)+iphdrlen+sizeof(struct udphdr));
    }
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Open the capture interface
    char *dev = argv[1]; // "lo"
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open live pcap: %s\n", errbuf);
        return 1;
    }

    // Apply a BPF filter to capture only UDP packets where source port is 53 (DNS responses)
    struct bpf_program fp;
    char filter_exp[] = "udp src port 53";  // Only capture DNS responses (UDP source port 53)
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start packet capture loop
    printf("Start listening for DNS responses\n");
    if (pcap_loop(handle, 0, packet_parser, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    return 0;
}