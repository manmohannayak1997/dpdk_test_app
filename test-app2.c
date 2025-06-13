// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

void print_menu() {
    printf("Supported commands:\n");
    printf("  send udp   - Generate and dump a dummy UDP packet\n");
    printf("  send tcp   - Generate and dump a dummy TCP packet\n");
    printf("  quit       - Exit the application\n");
}

void dump_packet(const uint8_t *pkt, size_t len) {
    printf("Packet dump (%zu bytes):\n", len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", pkt[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void send_udp() {
    uint8_t pkt[] = {
        // Ethernet header (dummy)
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
        // IPv4 header
        0x45,0x00,0x00,0x1c,0x00,0x00,0x40,0x00,0x40,0x11,0x00,0x00,
        0xc0,0xa8,0x01,0x01, 0xc0,0xa8,0x01,0x02,
        // UDP header
        0x30,0x39,0x00,0x35,0x00,0x08,0x00,0x00
    };
    dump_packet(pkt, sizeof(pkt));
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt + 14);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(pkt + 14 + sizeof(struct rte_ipv4_hdr));
    printf("Parsed UDP: src_ip=%x dst_ip=%x src_port=%u dst_port=%u\n",
        rte_be_to_cpu_32(ip->src_addr), rte_be_to_cpu_32(ip->dst_addr),
        rte_be_to_cpu_16(udp->src_port), rte_be_to_cpu_16(udp->dst_port));
}

void send_tcp() {
    uint8_t pkt[] = {
        // Ethernet header (dummy)
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
        // IPv4 header
        0x45,0x00,0x00,0x28,0x00,0x00,0x40,0x00,0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
        // TCP header
        0x30,0x39,0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00,0x00,0x00,0x00,0x00
    };
    dump_packet(pkt, sizeof(pkt));
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt + 14);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(pkt + 14 + sizeof(struct rte_ipv4_hdr));
    printf("Parsed TCP: src_ip=%x dst_ip=%x src_port=%u dst_port=%u\n",
        rte_be_to_cpu_32(ip->src_addr), rte_be_to_cpu_32(ip->dst_addr),
        rte_be_to_cpu_16(tcp->src_port), rte_be_to_cpu_16(tcp->dst_port));
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        printf("EAL init failed\n");
        return -1;
    }

    print_menu();
    char cmd[128];
    while (1) {
        printf("test_app> ");
        if (!fgets(cmd, sizeof(cmd), stdin))
            break;
        cmd[strcspn(cmd, "\n")] = 0;
        if (strcmp(cmd, "send udp") == 0) {
            send_udp();
        } else if (strcmp(cmd, "send tcp") == 0) {
            send_tcp();
        } else if (strcmp(cmd, "quit") == 0) {
            break;
        } else {
            printf("Please enter a valid command.\n");
            print_menu();
        }
    }

    rte_eal_cleanup();
    return 0;
}