#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#include "systems_headers.h"
#include "subuff.h"
#include "ethernet.h"
#include "ip.h"

#define TCP_ACK 0x01
#define TCP_PSH 0x02
#define TCP_RST 0x04
#define TCP_SYN 0x08
#define TCP_FIN 0x10
#define TCP_HDR_LEN sizeof(struct tcphdr)

#define DEBUG_TCP
#ifdef DEBUG_TCP
#define debug_tcp_hdr(hdr, socket, sub)                                  \
    do {                                                                \
        printf("TCP" \
               "Flags [A%uP%uR%uS%uF%u], seq %u, ack %u, win %u", \
               hdr->ack, hdr->psh, hdr->rst, hdr->syn, hdr->fin, hdr->seq, \
               hdr->ack, hdr->win); \
    } while (0)


#else
#define debug_tcp_hdr(hdr, socket, sub)
#endif

struct tcphdr {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seq;
    uint32_t ack_seq;
    unsigned int data_offset :4;
    unsigned int reserved : 4;
    unsigned int cwr : 1;
    unsigned int ece : 1;
    unsigned int urg : 1;
    unsigned int ack : 1;
    unsigned int psh : 1;
    unsigned int rst : 1;
    unsigned int syn : 1;
    unsigned int fin : 1;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
    uint8_t data[];
} __attribute__((packed));



int tcp_ack(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, int ack_num);

int tcp_syn(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num);

int tcp_tx(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, void *data, ssize_t data_length);


int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif
