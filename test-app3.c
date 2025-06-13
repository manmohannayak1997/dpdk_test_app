// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#define MAX_CMD_LEN 128
#define HASH_ENTRIES 1024

struct five_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} __attribute__((packed));

struct packet_entry {
    struct five_tuple key;
    uint8_t packet[64];
    uint16_t pkt_len;
};

static struct rte_hash *hash = NULL;

void print_menu() {
    printf("Supported commands:\n");
    printf("  send udp   - Generate and dump a dummy UDP packet\n");
    printf("  send tcp   - Generate and dump a dummy TCP packet\n");
    printf("  display all- Display all hash table entries\n");
    printf("  delete <src_ip> <dst_ip> <src_port> <dst_port> <proto> - Delete entry\n");
    printf("  flush      - Clear the hash table\n");
    printf("  quit       - Exit the application\n");
}

void dump_packet(const uint8_t *pkt, uint16_t len) {
    printf("Packet dump (%u bytes):\n", len);
    for (uint16_t i = 0; i < len; ++i) {
        printf("%02x ", pkt[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void send_udp() {
    struct packet_entry *entry = rte_zmalloc(NULL, sizeof(*entry), 0);
    if (!entry) {
        printf("Memory alloc failed\n");
        return;
    }
    entry->key.src_ip = RTE_IPV4(192,168,1,1);
    entry->key.dst_ip = RTE_IPV4(192,168,1,2);
    entry->key.src_port = rte_cpu_to_be_16(12345);
    entry->key.dst_port = rte_cpu_to_be_16(53);
    entry->key.proto = IPPROTO_UDP;

    uint8_t pkt[] = {
        // Ethernet header (dummy)
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
        // IPv4 header
        0x45,0x00,0x00,0x1c,0x00,0x00,0x40,0x00,0x40,0x11,0x00,0x00,
        0xc0,0xa8,0x01,0x01, 0xc0,0xa8,0x01,0x02,
        // UDP header
        0x30,0x39,0x00,0x35,0x00,0x08,0x00,0x00
    };
    entry->pkt_len = sizeof(pkt);
    memcpy(entry->packet, pkt, entry->pkt_len);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(entry->packet + 14);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(entry->packet + 14 + sizeof(struct rte_ipv4_hdr));
    printf("Parsed UDP: src_ip=%x dst_ip=%x src_port=%u dst_port=%u\n",
        rte_be_to_cpu_32(ip->src_addr), rte_be_to_cpu_32(ip->dst_addr),
        rte_be_to_cpu_16(udp->src_port), rte_be_to_cpu_16(udp->dst_port));

    int ret = rte_hash_add_key_data(hash, &entry->key, entry);
    if (ret < 0) {
        printf("Hash insert failed (maybe duplicate)\n");
        rte_free(entry);
        return;
    }
    printf("UDP packet inserted into hash table.\n");
    dump_packet(entry->packet, entry->pkt_len);
}

void send_tcp() {
    struct packet_entry *entry = rte_zmalloc(NULL, sizeof(*entry), 0);
    if (!entry) {
        printf("Memory alloc failed\n");
        return;
    }
    entry->key.src_ip = RTE_IPV4(10,0,0,1);
    entry->key.dst_ip = RTE_IPV4(10,0,0,2);
    entry->key.src_port = rte_cpu_to_be_16(12345);
    entry->key.dst_port = rte_cpu_to_be_16(80);
    entry->key.proto = IPPROTO_TCP;

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
    entry->pkt_len = sizeof(pkt);
    memcpy(entry->packet, pkt, entry->pkt_len);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(entry->packet + 14);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(entry->packet + 14 + sizeof(struct rte_ipv4_hdr));
    printf("Parsed TCP: src_ip=%x dst_ip=%x src_port=%u dst_port=%u\n",
        rte_be_to_cpu_32(ip->src_addr), rte_be_to_cpu_32(ip->dst_addr),
        rte_be_to_cpu_16(tcp->src_port), rte_be_to_cpu_16(tcp->dst_port));

    int ret = rte_hash_add_key_data(hash, &entry->key, entry);
    if (ret < 0) {
        printf("Hash insert failed (maybe duplicate)\n");
        rte_free(entry);
        return;
    }
    printf("TCP packet inserted into hash table.\n");
    dump_packet(entry->packet, entry->pkt_len);
}

void display_all() {
    printf("Hash table entries:\n");
    const void *next_key;
    void *next_data;
    uint32_t iter = 0;
    while (rte_hash_iterate(hash, &next_key, &next_data, &iter) >= 0) {
        struct packet_entry *entry = (struct packet_entry *)next_data;
        printf("src_ip=%x dst_ip=%x src_port=%u dst_port=%u proto=%u\n",
            entry->key.src_ip, entry->key.dst_ip,
            rte_be_to_cpu_16(entry->key.src_port), rte_be_to_cpu_16(entry->key.dst_port),
            entry->key.proto);
        dump_packet(entry->packet, entry->pkt_len);
    }
}

void delete_entry(char *args) {
    struct five_tuple key;
    int cnt = sscanf(args, "%x %x %hu %hu %hhu",
        &key.src_ip, &key.dst_ip, &key.src_port, &key.dst_port, &key.proto);
    if (cnt != 5) {
        printf("Usage: delete <src_ip> <dst_ip> <src_port> <dst_port> <proto>\n");
        return;
    }
    int ret = rte_hash_del_key(hash, &key);
    if (ret < 0)
        printf("Entry not found.\n");
    else
        printf("Entry deleted.\n");
}

void flush_table() {
    uint32_t iter = 0;
    const void *next_key;
    void *next_data;
    while (rte_hash_iterate(hash, &next_key, &next_data, &iter) >= 0) {
        struct packet_entry *entry = (struct packet_entry *)next_data;
        rte_free(entry);
    }
    rte_hash_reset(hash);
    printf("Hash table flushed.\n");
}

int main(int argc, char **argv) {
    struct rte_hash_parameters hash_params = {
        .name = "five_tuple_hash",
        .entries = HASH_ENTRIES,
        .key_len = sizeof(struct five_tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
    };

    if (rte_eal_init(argc, argv) < 0) {
        printf("EAL init failed\n");
        return -1;
    }

    hash = rte_hash_create(&hash_params);
    if (!hash) {
        printf("Hash table creation failed\n");
        return -1;
    }

    print_menu();

    char cmd[MAX_CMD_LEN];
    while (1) {
        printf("test_app> ");
        if (!fgets(cmd, sizeof(cmd), stdin))
            break;
        cmd[strcspn(cmd, "\n")] = 0;

        if (strcmp(cmd, "send udp") == 0) {
            send_udp();
        } else if (strcmp(cmd, "send tcp") == 0) {
            send_tcp();
        } else if (strcmp(cmd, "display all") == 0) {
            display_all();
        } else if (strncmp(cmd, "delete ", 7) == 0) {
            delete_entry(cmd + 7);
        } else if (strcmp(cmd, "flush") == 0) {
            flush_table();
        } else if (strcmp(cmd, "quit") == 0) {
            break;
        } else {
            printf("Please enter a valid command.\n");
            print_menu();
        }
    }

    flush_table();
    rte_hash_free(hash);
    rte_eal_cleanup();
    return