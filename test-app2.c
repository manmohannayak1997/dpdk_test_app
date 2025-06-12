// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>

#define MBUF_CACHE_SIZE 250
#define NUM_MBUFS 8191

static struct rte_mempool *mbuf_pool = NULL;

void dump_udp_packet() {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        printf("Failed to allocate mbuf\n");
        return;
    }

    mbuf->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
    mbuf->pkt_len = mbuf->data_len;

    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(eth + 1);
    struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);

    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->hdr_checksum = 0;
    ip->src_addr = htonl(IPv4(192, 168, 1, 1));
    ip->dst_addr = htonl(IPv4(192, 168, 1, 2));

    udp->src_port = htons(1234);
    udp->dst_port = htons(5678);
    udp->dgram_len = htons(sizeof(struct udp_hdr));
    udp->dgram_cksum = 0;

    printf("Dummy UDP Packet:\n");
    printf("IPv4 Src: %s, Dst: %s\n", "192.168.1.1", "192.168.1.2");
    printf("UDP Src Port: %u, Dst Port: %u\n", ntohs(udp->src_port), ntohs(udp->dst_port));

    rte_pktmbuf_free(mbuf);
}

void dump_tcp_packet() {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        printf("Failed to allocate mbuf\n");
        return;
    }

    mbuf->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);
    mbuf->pkt_len = mbuf->data_len;

    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(eth + 1);
    struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);

    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = htonl(IPv4(10, 0, 0, 1));
    ip->dst_addr = htonl(IPv4(10, 0, 0, 2));

    tcp->src_port = htons(1111);
    tcp->dst_port = htons(2222);
    tcp->sent_seq = htonl(0);
    tcp->recv_ack = htonl(0);
    tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
    tcp->tcp_flags = 0x10;  // ACK
    tcp->rx_win = htons(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    printf("Dummy TCP Packet:\n");
    printf("IPv4 Src: %s, Dst: %s\n", "10.0.0.1", "10.0.0.2");
    printf("TCP Src Port: %u, Dst Port: %u\n", ntohs(tcp->src_port), ntohs(tcp->dst_port));

    rte_pktmbuf_free(mbuf);
}

int main(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    char input[256];
    printf("Enter command: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Error reading command\n");
        return -1;
    }

    if (strncmp(input, "send udp", 8) == 0) {
        dump_udp_packet();
    } else if (strncmp(input, "send tcp", 8) == 0) {
        dump_tcp_packet();
    } else {
        printf("Please enter a valid command (send udp | send tcp)\n");
    }

    return 0;
}
