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
#include "config.h"
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "tcp.h"
#include "utilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define VERBOSE 1

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

uint16_t  rand_uint16(){
    uint16_t r = 0;
    for(int i = 0; i<16; i++){
        r = r*2 + rand()%2;
    }
    return r;
}

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
        stream->dst_port = rand_uint16();

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
        int optlen = 0;

        // Set/get the destination addr
        stream_data->dst_addr = (((struct sockaddr_in *)addr)->sin_addr).s_addr;
        stream_data->src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);
        uint16_t dst_port = ntohs(((struct sockaddr_in *)addr)->sin_port);
        stream_data->dst_port = dst_port;

        struct subuff *sub = alloc_sub(ETH_HDR_LEN+IP_HDR_LEN);
        int return_ip_out;
        do {
            if (VERBOSE) printf("[?] Sending lookup request for dst_addr...\n");
            return_ip_out = ip_output(htonl(stream_data->dst_addr), sub);
            printf("[=] Waiting on resolve\n");
            sleep(1);
        } while (return_ip_out==-11);

        if (return_ip_out==-1) free_sub(sub);

        if (VERBOSE) printf("[+] Constructing TCP_SYN...\n");
        sub = tcp_base(stream_data, stream_data->dst_addr, dst_port);
        struct tcphdr *tcp_hdr = (struct tcphdr *)sub->data;
        tcp_hdr->seq=htonl(stream_data->initial_seq);
        stream_data->last_unacked_seq = stream_data->initial_seq;
        tcp_hdr->ack_seq=0;
        tcp_hdr->syn=1;
        tcp_hdr->header_len=6;//waarom hier 6? welke optie is gezet? | Alleen MSS, de actuelle tcp header structuur heeft dus 8 extra bytes 
        tcp_hdr->option_type = 2;
        tcp_hdr->option_length = 4;
        tcp_hdr->option_value = htons(0x534);

        //Setup the Header CSUM
        tcp_hdr->csum = do_tcp_csum((void *)tcp_hdr, sizeof(struct tcphdr), IPP_TCP, stream_data->src_addr, stream_data->dst_addr);
        debug_tcp_hdr(tcp_hdr);

        return_ip_out = ip_output(htonl(stream_data->dst_addr), sub);
        if (return_ip_out>=0) {
            // Sent some bytes?
            stream_data->state=1;
            while(stream_data->state<2 && stream_data->state>=0) {
                if (VERBOSE) printf("[~] Waiting on state change, cur=%d, expected=>1\n", stream_data->state);
                sleep(2);
            }
            if (VERBOSE) printf("[~] Done waiting, reached state %d\n",stream_data->state);
            if (stream_data->state>=0) return 0;
            if (VERBOSE) printf("[!] Unable to make connection with destinationhost.\n");
        } else if (return_ip_out==-1){
            printf("[!] No route to host?\n");
        } else {
            printf("[!] Unknown err: %d\n", return_ip_out);
        }
        free_sub(sub);
        return -1;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// ANP Milestone 3
struct subuff *tcp_base(struct tcp_stream_info* stream_data, uint32_t dst_addr, uint16_t dst_port){
        struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN );
        sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN );
        sub->protocol = IPP_TCP; //Set TCP protocol
        struct tcphdr *tcp_hdr = (struct tcphdr*) sub_push(sub, TCP_HDR_LEN);

        tcp_hdr->srcport = htons(stream_data->stream_port);
        tcp_hdr->dstport = htons(dst_port);
        tcp_hdr->header_len = 5;//no options set
        tcp_hdr->win=htons(8760);
        tcp_hdr->urp=0;

        return sub;
}

int tcp_tx(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, void *data, ssize_t data_length){

}

int tcp_rx(struct subuff *sub){
    struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
    struct tcp_stream_info *stream_data = open_streams_port[ntohs(tcp_header->dstport)];

    if (ntohl(tcp_header->ack_seq) == stream_data->last_unacked_seq+1) {
        // VALID PACKET ORDERING CHECKED
        switch (stream_data->state) {
            case 1: // EXPECTING SYN-ACK
                if (tcp_header->ack && tcp_header->syn) { 
                    stream_data->last_unacked_seq=tcp_header->seq+1;

                    struct subuff* synack = tcp_base(stream_data, ip_header->saddr, ntohs(tcp_header->srcport));
                    struct tcphdr *reply_hdr = (struct tcphdr *)synack->data;
                    memcpy(reply_hdr, tcp_header, TCP_HDR_LEN);
                    uint16_t storage = reply_hdr->dstport;
                    reply_hdr->dstport = reply_hdr->srcport;
                    reply_hdr->srcport = storage;
                    reply_hdr->header_len = 6; //because we set ack?
                    reply_hdr->syn=0;
                    reply_hdr->ack=1;
                    reply_hdr->ack_seq = htonl(ntohl(tcp_header->seq)+1);
                    reply_hdr->seq = tcp_header->ack_seq;// Increment Seq
                    stream_data->last_unacked_seq = ntohl(1); //FIXME maybe not hardcode this
                    reply_hdr->csum = 0;
                    reply_hdr->option_type = 1;
                    reply_hdr->option_length=1;
                    reply_hdr->option_value=0x100;
                    reply_hdr->csum = do_tcp_csum((void *)reply_hdr, sizeof(struct tcphdr), IPP_TCP, stream_data->src_addr, stream_data->dst_addr);

                    ip_output(ip_header->saddr, synack);
                    stream_data->state+=1;
                    break;
                } else if (tcp_header->rst || tcp_header->fin) {
                    // Teardown/End connection
                    if (VERBOSE) printf("[!] Recieved request to end connection (RST/FIN).\n");
                    stream_data->state=-1;
                    goto drop_pkt;
                } else {
                    if (VERBOSE) printf("[!] Dropping packet, not expected by state=%d\n",stream_data->state);
                    goto drop_pkt;
                }
            case 2: // We initiated the FIN and expect a FIN ACK or ACK
                if (tcp_header->fin && tcp_header->ack) {
                    printf("[!]%s\n", " Received a FIN-ACK from server");

                } else if (tcp_header->ack) {
                    // The server still sends data so handle this state (FIN-WAIT-2)
                    printf("[!]%s\n", "There is an ACK after initiating the FIN");
                }
            default: // ESTABLISHED connection, appending data to stream buffer
                goto drop_pkt;
        }
    } else {
        printf("TCP SYN ACK was not correct, %u!=%u\n", ntohl(tcp_header->ack_seq), stream_data->last_unacked_seq);
    }
drop_pkt:
    free_sub(sub);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = MAX_CUSTOM_TCP_FD>sockfd && sockfd>MIN_CUSTOM_TCP_FD;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = MAX_CUSTOM_TCP_FD>sockfd && sockfd>MIN_CUSTOM_TCP_FD;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = MAX_CUSTOM_TCP_FD>sockfd && sockfd>MIN_CUSTOM_TCP_FD;
    if(is_anp_sockfd) {
        // struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
        // struct tcphdr *tcp_header = (struct tcphdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
        struct tcp_stream_info *stream_data = open_streams_fd[sockfd-MIN_CUSTOM_TCP_FD];

        struct subuff* finack = tcp_base(stream_data, stream_data->dst_addr, stream_data->dst_port); //TODO add dst_port to stream data struct
        struct tcphdr *reply_hdr = (struct tcphdr *)finack->data;
        printf("[!!!] last unacked seq %ul\n",stream_data->last_unacked_seq );
        reply_hdr->header_len = 6;
        reply_hdr->fin=1;
        reply_hdr->ack=1;
        reply_hdr->ack_seq = htonl(stream_data->last_unacked_seq);
        reply_hdr->seq = htonl(stream_data->last_unacked_seq);// Increment Seq
        stream_data->last_unacked_seq = stream_data->last_unacked_seq+1;
        printf("[sequence numbers finack]: %d, %d, %d\n", reply_hdr->ack_seq, reply_hdr->seq, stream_data->last_unacked_seq);
        reply_hdr->csum = 0;
        reply_hdr->option_type = 1;
        reply_hdr->option_length=1;
        reply_hdr->option_value=0x100;
        reply_hdr->csum = do_tcp_csum((void *)reply_hdr, sizeof(struct tcphdr), IPP_TCP, stream_data->src_addr, stream_data->dst_addr);
        stream_data->state+=1;

        int return_output = ip_output(htonl(stream_data->dst_addr), finack);
        return return_output;
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

