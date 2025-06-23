// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
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
    printf("  send udp src_ip <ip> dst_ip <ip> src_port <port> dst_port <port>\n");
    printf("  send tcp src_ip <ip> dst_ip <ip> src_port <port> dst_port <port>\n");
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

static int parse_ip(const char *str, uint32_t *out) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1)
        return -1;
    *out = addr.s_addr;
    return 0;
}

static int parse_port(const char *str, uint16_t *out) {
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val < 1 || val > 65535)
        return -1;
    *out = htons((uint16_t)val);
    return 0;
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
    char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_addr;
    dst_addr.s_addr = ip->dst_addr;
    printf("Parsed UDP: src_ip=%s dst_ip=%s src_port=%u dst_port=%u\n",
        inet_ntop(AF_INET, &src_addr, srcbuf, sizeof(srcbuf)),
        inet_ntop(AF_INET, &dst_addr, dstbuf, sizeof(dstbuf)),
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
    char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_addr;
    dst_addr.s_addr = ip->dst_addr;
    printf("Parsed TCP: src_ip=%s dst_ip=%s src_port=%u dst_port=%u\n",
        inet_ntop(AF_INET, &src_addr, srcbuf, sizeof(srcbuf)),
        inet_ntop(AF_INET, &dst_addr, dstbuf, sizeof(dstbuf)),
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

void send_udp_param(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    struct packet_entry *entry = rte_zmalloc(NULL, sizeof(*entry), 0);
    if (!entry) {
        printf("Memory alloc failed\n");
        return;
    }
    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = src_port;
    entry->key.dst_port = dst_port;
    entry->key.proto = IPPROTO_UDP;

    uint8_t pkt[] = {
        // Ethernet header (dummy)
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
        // IPv4 header
        0x45,0x00,0x00,0x1c,0x00,0x00,0x40,0x00,0x40,0x11,0x00,0x00,
        0,0,0,0, 0,0,0,0,
        // UDP header
        0,0,0,0,0x00,0x08,0x00,0x00
    };
    memcpy(pkt+26, &src_ip, 4);
    memcpy(pkt+30, &dst_ip, 4);
    memcpy(pkt+34, &src_port, 2);
    memcpy(pkt+36, &dst_port, 2);

    entry->pkt_len = sizeof(pkt);
    memcpy(entry->packet, pkt, entry->pkt_len);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(entry->packet + 14);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(entry->packet + 14 + sizeof(struct rte_ipv4_hdr));
    char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_addr;
    dst_addr.s_addr = ip->dst_addr;
    printf("Parsed UDP: src_ip=%s dst_ip=%s src_port=%u dst_port=%u\n",
        inet_ntop(AF_INET, &src_addr, srcbuf, sizeof(srcbuf)),
        inet_ntop(AF_INET, &dst_addr, dstbuf, sizeof(dstbuf)),
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

void send_tcp_param(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    struct packet_entry *entry = rte_zmalloc(NULL, sizeof(*entry), 0);
    if (!entry) {
        printf("Memory alloc failed\n");
        return;
    }
    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = src_port;
    entry->key.dst_port = dst_port;
    entry->key.proto = IPPROTO_TCP;

    uint8_t pkt[] = {
        // Ethernet header (dummy)
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
        // IPv4 header
        0x45,0x00,0x00,0x28,0x00,0x00,0x40,0x00,0x40,0x06,0x00,0x00,
        0,0,0,0, 0,0,0,0,
        // TCP header
        0,0,0,0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00,0x00,0x00,0x00,0x00
    };
    memcpy(pkt+26, &src_ip, 4);
    memcpy(pkt+30, &dst_ip, 4);
    memcpy(pkt+34, &src_port, 2);
    memcpy(pkt+36, &dst_port, 2);

    entry->pkt_len = sizeof(pkt);
    memcpy(entry->packet, pkt, entry->pkt_len);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(entry->packet + 14);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(entry->packet + 14 + sizeof(struct rte_ipv4_hdr));
    char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_addr;
    dst_addr.s_addr = ip->dst_addr;
    printf("Parsed TCP: src_ip=%s dst_ip=%s src_port=%u dst_port=%u\n",
        inet_ntop(AF_INET, &src_addr, srcbuf, sizeof(srcbuf)),
        inet_ntop(AF_INET, &dst_addr, dstbuf, sizeof(dstbuf)),
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
    char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
    while (rte_hash_iterate(hash, &next_key, &next_data, &iter) >= 0) {
        struct packet_entry *entry = (struct packet_entry *)next_data;
        struct in_addr src, dst;
        src.s_addr = entry->key.src_ip;
        dst.s_addr = entry->key.dst_ip;
        printf("src_ip=%s dst_ip=%s src_port=%u dst_port=%u proto=%u\n",
            inet_ntop(AF_INET, &src, srcbuf, sizeof(srcbuf)),
            inet_ntop(AF_INET, &dst, dstbuf, sizeof(dstbuf)),
            rte_be_to_cpu_16(entry->key.src_port), rte_be_to_cpu_16(entry->key.dst_port),
            entry->key.proto);
        dump_packet(entry->packet, entry->pkt_len);
    }
}

void delete_entry(char *args) {
    struct five_tuple key;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    uint8_t proto;
    int cnt = sscanf(args, "%15s %15s %hu %hu %hhu",
        src_ip_str, dst_ip_str, &src_port, &dst_port, &proto);
    if (cnt != 5) {
        printf("Usage: delete <src_ip> <dst_ip> <src_port> <dst_port> <proto>\n");
        return;
    }
    if (parse_ip(src_ip_str, &key.src_ip) != 0 || parse_ip(dst_ip_str, &key.dst_ip) != 0) {
        printf("Invalid IP format for delete.\n");
        return;
    }
    key.src_port = htons(src_port);
    key.dst_port = htons(dst_port);
    key.proto = proto;
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

        // Enhanced command parsing for parameterized send udp/tcp
        char proto[8], key1[16], val1[32], key2[16], val2[32], key3[16], val3[32], key4[16], val4[32];
        int n = sscanf(cmd, "send %7s %15s %31s %15s %31s %15s %31s %15s %31s",
            proto, key1, val1, key2, val2, key3, val3, key4, val4);

        if (n >= 9 && (strcmp(proto, "udp") == 0 || strcmp(proto, "tcp") == 0)) {
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            int found_src_ip = 0, found_dst_ip = 0, found_src_port = 0, found_dst_port = 0;
            for (int i = 1; i < 8; i += 2) {
                char *k = NULL, *v = NULL;
                switch (i) {
                    case 1: k = key1; v = val1; break;
                    case 3: k = key2; v = val2; break;
                    case 5: k = key3; v = val3; break;
                    case 7: k = key4; v = val4; break;
                }
                if (strcmp(k, "src_ip") == 0) {
                    if (parse_ip(v, &src_ip) == 0) found_src_ip = 1;
                    else { printf("Invalid src_ip format.\n"); goto invalid; }
                } else if (strcmp(k, "dst_ip") == 0) {
                    if (parse_ip(v, &dst_ip) == 0) found_dst_ip = 1;
                    else { printf("Invalid dst_ip format.\n"); goto invalid; }
                } else if (strcmp(k, "src_port") == 0) {
                    if (parse_port(v, &src_port) == 0) found_src_port = 1;
                    else { printf("Invalid src_port.\n"); goto invalid; }
                } else if (strcmp(k, "dst_port") == 0) {
                    if (parse_port(v, &dst_port) == 0) found_dst_port = 1;
                    else { printf("Invalid dst_port.\n"); goto invalid; }
                } else {
                    printf("Unknown parameter: %s\n", k);
                    goto invalid;
                }
            }
            if (found_src_ip && found_dst_ip && found_src_port && found_dst_port) {
                if (strcmp(proto, "udp") == 0)
                    send_udp_param(src_ip, dst_ip, src_port, dst_port);
                else
                    send_tcp_param(src_ip, dst_ip, src_port, dst_port);
                continue;
            }
        }
invalid:
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
    return 0;
}