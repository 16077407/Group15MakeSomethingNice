/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <netinet/in.h>
#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "tcp.h"
#include "utilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct tcp_stream_info *open_streams_port[1<<16-1];
struct tcp_stream_info *open_streams_fd[MAX_CUSTOM_TCP_FD-MIN_CUSTOM_TCP_FD];
int LAST_ISSUED_TCP_FD = MIN_CUSTOM_TCP_FD;

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
        char * * ubp_av, void (*init) (void), void (*fini) (void), \
        void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) {
        // Setup TCPStream struct to keep track of state and dest
        struct tcp_stream_info *stream = malloc(sizeof(struct tcp_stream_info));
        stream->state = 0; // uninitialized
        stream->bytes_tx = 0;
        stream->bytes_rx = 0;
        stream->last_unacked_seq = 0;
        stream->initial_seq = 3149642683;
        stream->stream_port = rand_uint16();

        open_streams_port[stream->stream_port] = stream; // Store for later by port

        // Return useful FD
        LAST_ISSUED_TCP_FD += 1;
        stream->fd = LAST_ISSUED_TCP_FD;
        open_streams_fd[stream->fd-MIN_CUSTOM_TCP_FD] = stream;

        if (LAST_ISSUED_TCP_FD>MAX_CUSTOM_TCP_FD) {
            free(stream);
            return -ENOSYS;
        } else {
            return stream->fd;
        }
        return -ENOSYS;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = MAX_CUSTOM_TCP_FD>sockfd && sockfd>MIN_CUSTOM_TCP_FD;
    if(is_anp_sockfd){
        struct tcp_stream_info *stream_data = open_streams_fd[sockfd-MIN_CUSTOM_TCP_FD];

        printf("\n[DBG] ETH_HDR_LEN = %ld\n\tIP_HDR_LEN = %ld\n\tSUM = %ld\n\tTCP_HDR_LEN = %ld\n\tTOTAL = %ld\n\n", ETH_HDR_LEN, IP_HDR_LEN, ETH_HDR_LEN+IP_HDR_LEN, TCP_HDR_LEN, TCP_HDR_LEN+ETH_HDR_LEN+IP_HDR_LEN);

        // Set/get the destination addr
        uint32_t dst_addr = (((struct sockaddr_in *)addr)->sin_addr).s_addr;
        uint16_t dst_port = ((struct sockaddr_in *)addr)->sin_port;
        printf("[!] I believe the dest addr is: %s:%d\n", inet_ntoa(((struct sockaddr_in *)addr)->sin_addr), dst_port);

        struct subuff *sub = alloc_sub(ETH_HDR_LEN+IP_HDR_LEN);
        printf("[?] Sending lookup request for dst_addr...\n");
        int return_ip_out = ip_output(htonl(dst_addr), sub);
        hexDump("[X] Dump of constructed subuff", sub->head, ETH_HDR_LEN+IP_HDR_LEN);

        if (return_ip_out!=-11 && return_ip_out<0) return -1;
        while(ip_output(htonl(dst_addr), sub)==-11){
            printf("[=] Waiting on resolve\n");
            sleep(1);
        }

        printf("[+] Constructing TCP_SYN...\n");
        free_sub(sub);
        sub = tcp_base(stream_data, dst_addr, dst_port);
        struct tcphdr *tcp_hdr = (struct tcphdr *)sub->data;
        tcp_hdr->seq=htonl(stream_data->initial_seq);
        tcp_hdr->ack_seq=htonl(2863311530);
        tcp_hdr->syn=1;
        tcp_hdr->header_len=6;
        tcp_hdr->csum = htons(do_tcp_csum((void *)tcp_hdr, sizeof(struct tcphdr), IPP_TCP, ip_str_to_n32("10.0.0.4"), dst_addr));
        debug_tcp_hdr(tcp_hdr);

        // We now have the set IP Headers to fiddle with
        /* struct iphdr* ip_hdr = (struct iphdr *)sub->data; */
        /* sub->data+=IP_HDR_LEN; // Reset Data to pre ip_output push */
        /* sub->len-=IP_HDR_LEN; // Reset Len to pre ip_output push  */
        // We can make changes to the ip header but it'll be reset at push
        return_ip_out = ip_output(htonl(dst_addr), sub);
        printf("[$] Result of ip_output: %d\n\n", return_ip_out); 
        hexDump("[X] Dump of Packet sent", sub->head, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN );

        if (return_ip_out>=0) {
            // Sent some bytes?
            while(stream_data->state<2 && stream_data->state>=0) {
                printf("[~] Waiting on state change, cur=%d, expected=>2\n", stream_data->state);
                sleep(2);
            }
            printf("[~] Done waiting, reached state %d\n",stream_data->state);
            free_sub(sub);
            return 0;
        }
        if (return_ip_out==-1){
            printf("[!] No route to host?\n");
            return -1;
        }

        /* int counter = 0; */
        /* while(counter<3){ */
/*  */
            /* counter+=1; */
            /* sleep(1); */
        /* } */
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// ANP Milestone 3 
struct subuff *tcp_base(struct tcp_stream_info* stream_data, uint32_t dst_addr, uint16_t dst_port){ 
        struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN );
        sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN );
        sub->protocol = IPP_TCP; //Set TCP protocol
        // Set TCP Header Values
        //
        struct tcphdr *tcp_hdr = (struct tcphdr*) sub_push(sub, TCP_HDR_LEN); //sub->head+ETH_HDR_LEN+IP_HDR_LEN;

        tcp_hdr->srcport = stream_data->stream_port;
        tcp_hdr->dstport = dst_port;
        tcp_hdr->header_len = 5;
        tcp_hdr->win=htons(4096);
        tcp_hdr->urp=0;

        return sub;
}

int tcp_ack(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, int ack_num){
    struct tcphdr* tcp_hdr = (struct tcphdr*) sub_push(sub, TCP_HDR_LEN);
    sub->protocol = IPP_TCP;

    tcp_hdr->srcport = (stream->stream_port); // FIXME: Set to random 16bit wide (u)integer
    tcp_hdr->dstport = (1);
    tcp_hdr->seq = seq_num;
    tcp_hdr->ack_seq = ack_num;
    tcp_hdr->header_len = 5;
    tcp_hdr->ack=1;
    tcp_hdr->win=0;
    tcp_hdr->urp = 0;
    tcp_hdr->csum = do_tcp_csum((void *)tcp, sizeof(struct tcphdr), IPP_TCP, ip_str_to_n32("10.0.0.4"), ip->saddr);

    int return_ip_out = ip_output(ip->saddr, sub);
    printf("Result of ip_output ack: %d\n",return_ip_out);
}

int tcp_tx(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, void *data, ssize_t data_length){

}

int tcp_rx(struct subuff *sub){
    printf("\n[!] RECIEVED TCP PACKET\n\n");
    struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr *) ip_header->data;
    struct tcp_stream_info *stream_data = open_streams_port[tcp_header->dstport];

    if (tcp_header->ack_seq == (stream_data->last_unacked_seq)) {
        // VALID PACKET ORDERING CHECKED
        switch (stream_data->state) {
            case 0: // EXPECTING SYN-ACK
                if (tcp_header->ack && tcp_header->syn) {
                    stream_data->state+=1;
                    // tcp_ack(stream_data, ip_header, tcp_header, sub, tcp_header->seq+1, tcp_header->seq);
                    stream_data->last_unacked_seq=tcp_header->seq+1;
                    printf("[=] Recieved SYN-ACK, replyed with ACK and setting stream as ESTABLISHED\n");
                    break;
                } else {
                    goto drop_pkt;
                }
            default: // ESTABLISHED connection, appending data to stream buffer
                goto drop_pkt;
        }
    } else {
        printf("%s\n", "TCP SYN ACK was not correct");
    }
drop_pkt:
    free_sub(sub);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}


uint16_t  rand_uint16(){
    uint16_t r = 0;
    for(int i = 0; i<16; i++){
    r = r*2 + rand()%2;
    }
    printf("[#] Random number 16 bits unsigned int: %d\n", r );
    return r;
}
