// nfqueue_icmp_handler.cpp
//
// A simple C++ application that listens to Netfilter Queue #0,
// intercepts ICMP Echo Requests, converts them into Echo Replies,
// logs messages, and gracefully handles SIGTERM and SIGINT.
//
// Required Linux packages/libraries:
//   - libnetfilter-queue (development package: libnetfilter-queue-dev)
//   - libmnl (if needed by your distro for libnetfilter_queue)
//   - Standard C++ libraries
//
// To compile (example):
//   g++ nfqueue_icmp_handler.cpp -o nfqueue_icmp_handler -lnetfilter_queue
//
// Run with sufficient privileges (e.g., via sudo)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <iostream>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>       // for iphdr
#include <netinet/ip_icmp.h>  // for icmphdr
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

// Global flag for graceful termination
static volatile bool running = true;

// Signal handler to exit cleanly
void signalHandler(int sig) {
    std::cerr << "Signal " << sig << " caught, exiting...\n";
    running = false;
}

// Utility function to recalc the ICMP checksum
// This function computes the checksum over the ICMP header and data.
unsigned short compute_icmp_checksum(unsigned short *data, int len) {
    long sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    // Add left-over byte, if any
    if (len == 1) {
        sum += *(unsigned char*)data;
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

// Compute IP header checksum
uint16_t compute_ip_checksum(struct iphdr* iph, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)iph;

    // Sum all 16-bit words in the header
    for (int i = 0; i < len / 2; ++i) {
        sum += ntohs(ptr[i]);
    }

    // If header length is odd, add the last byte padded with zero
    if (len & 1) {
        sum += *((uint8_t*)iph + len - 1) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement in network byte order
    return htons(~sum);
}

// Utility function to log packet hexdump
void logPacketHexdump(const unsigned char* data, int length, const std::string& label) {
    std::cerr << label << " (" << length << " bytes):\n";
    for (int i = 0; i < length; ++i) {
        fprintf(stderr, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    if (length % 16 != 0) fprintf(stderr, "\n");
}

// Callback function for handling packets from NFQUEUE
static int handlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data)
{
    // Retrieve the packet id for later verdict operations
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    // Get the payload data from the nfq_data structure
    unsigned char *packetData;
    int len = nfq_get_payload(nfa, &packetData);
    if (len >= 0) {
        logPacketHexdump(packetData, len, "Raw packet from NFQUEUE");
        // Parse the IP header
        struct iphdr *ipHeader = (struct iphdr*)packetData;
        if (ipHeader->protocol == IPPROTO_ICMP) {
            // Calculate the start of the ICMP header
            int ipHeaderLen = ipHeader->ihl * 4;
            if (len >= ipHeaderLen + (int)sizeof(struct icmphdr)) {
                struct icmphdr *icmpHeader = (struct icmphdr*)(packetData + ipHeaderLen);
                // Check if this is an Echo Request (ICMP type 8)
                if (icmpHeader->type == ICMP_ECHO) {
                    std::cerr << "Received ICMP Echo Request from "
                        << inet_ntoa({ipHeader->saddr}) << " to "
                        << inet_ntoa({ipHeader->daddr}) << "\n";

                    // Swap source and destination IP addresses
                    uint32_t tmp_ip = ipHeader->saddr;
                    ipHeader->saddr = ipHeader->daddr;
                    ipHeader->daddr = tmp_ip;

                    // Recalculate IP checksum
                    ipHeader->check = 0;
                    ipHeader->check = compute_ip_checksum(ipHeader, ipHeaderLen);

                    // Modify to Echo Reply
                    icmpHeader->type = ICMP_ECHOREPLY;

                    // Set checksum to zero before recalculation
                    icmpHeader->checksum = 0;
                    // Recalculate the checksum for the ICMP header and its payload
                    int icmpLen = len - ipHeaderLen;
                    icmpHeader->checksum = compute_icmp_checksum((unsigned short*)icmpHeader, icmpLen);

                    std::cerr << "Converted to ICMP Echo Reply. Setting verdict NF_ACCEPT with modified payload.\n";

                    logPacketHexdump(packetData, len, "Packet after modification");
                    int verdict_result = nfq_set_verdict(qh, id, NF_ACCEPT, len, packetData);
                    if (verdict_result < 0) {
                        std::cerr << "Error: nfq_set_verdict() failed with code " << verdict_result << "\n";
                    }
                    std::cerr << "Converted to ICMP Echo Reply.\n";

                    // Accept and replace the packet with our modified version
                    return verdict_result;
                }
            }
        }
    }

    // For non-ICMP or non-echo-request packets, just accept without modification
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main() {
    // Register signal handlers for SIGTERM and SIGINT for graceful exit
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);

    std::cerr << "Starting NFQUEUE ICMP Handler...\n";

    // Open library handle for NFQUEUE
    struct nfq_handle *nfqHandle = nfq_open();
    if (!nfqHandle) {
        std::cerr << "Error during nfq_open()\n";
        exit(EXIT_FAILURE);
    }

    // Unbind existing nf_queue handler for AF_INET (if any) and bind to it
    if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
        std::cerr << "Error during nfq_unbind_pf()\n";
        nfq_close(nfqHandle);
        exit(EXIT_FAILURE);
    }
    if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
        std::cerr << "Error during nfq_bind_pf()\n";
        nfq_close(nfqHandle);
        exit(EXIT_FAILURE);
    }

    // Bind to queue 0 and set our callback function
    struct nfq_q_handle *queueHandle = nfq_create_queue(nfqHandle,  0, &handlePacket, NULL);
    if (!queueHandle) {
        std::cerr << "Error during nfq_create_queue()\n";
        nfq_close(nfqHandle);
        exit(EXIT_FAILURE);
    }

    // Set mode to copy the entire packet to userspace
    if (nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Can't set packet copy mode\n";
        nfq_destroy_queue(queueHandle);
        nfq_close(nfqHandle);
        exit(EXIT_FAILURE);
    }

    std::cerr << "Handler is running. Waiting for packets...\n";

    // Main loop to process packets
    int fd = nfq_fd(nfqHandle);
    char buf[4096] __attribute__((aligned));
    while (running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(nfqHandle, buf, rv);
        } else if (rv < 0 && errno == EINTR) {
            // Interrupted by signal, gracefully exit.
            continue;
        } else {
            std::cerr << "Error while receiving data\n";
            break;
        }
    }

    // Cleanup before exit
    std::cerr << "Cleaning up and exiting...\n";
    nfq_destroy_queue(queueHandle);
    nfq_close(nfqHandle);
    return 0;
}
