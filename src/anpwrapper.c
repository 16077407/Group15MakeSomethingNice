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

void *open_streams[1<<16-1];
void *open_streams_fd[MAX_CUSTOM_TCP_FD-MIN_CUSTOM_TCP_FD];
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
        //TODO: implement your logic here

        // Setup TCPStream struct to keep track of state and dest
        struct tcp_stream_info *stream = malloc(sizeof(struct tcp_stream_info));
        stream->state = 0; // uninitialized
        stream->bytes_tx = 0;
        stream->bytes_rx = 0;
        stream->last_unacked_seq = 0;
        stream->addrinfo = NULL;
        stream->header = malloc(sizeof(struct tcphdr));
        stream->header->srcport = 0;// set random outgoing port

        open_streams[stream->header->srcport] = stream; // Store for later by port

        // Return useful FD
        LAST_ISSUED_TCP_FD += 1;
        stream->fd = LAST_ISSUED_TCP_FD;
        open_streams_fd[stream->fd];

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
        struct subuff *sub = alloc_sub(TCP_HDR_LEN+10);
        sub_reserve(sub, TCP_HDR_LEN+10);
        struct tcphdr *tcp_hdr = (struct tcphdr*)(sub->head);

        // Set TCP Header Values
        uint32_t dst_addr = (((struct sockaddr_in *)addr)->sin_addr).s_addr;
        printf("[!] I believe the dest addr is: %s\n", inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
        tcp_hdr->srcport = 4224;
        tcp_hdr->dstport = ((struct sockaddr_in *)addr)->sin_port;
        tcp_hdr->seq = 1;
        tcp_hdr->ack_seq = 0;
        tcp_hdr->data_offset = 0;
        tcp_hdr->reserved = 0;
        tcp_hdr->syn=1;
        tcp_hdr->win=0;
        tcp_hdr->csum = -1;

        printf("[=] Passing made packet onto ip_output...\n");
        int return_ip_out = ip_output(dst_addr, sub);
        printf("[=] Result of ip_output: %d\n", return_ip_out);
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// ANP Milestone 3
int tcp_ack(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, int ack_num){
        return 0;
}

int tcp_tx(struct tcp_stream_info *stream, struct iphdr *ip, struct tcphdr *tcp, struct subuff *sub, int seq_num, void *data, ssize_t data_length){

}

int tcp_rx(struct subuff *sub){
    struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr *) ip_header->data;
    struct tcp_stream_info *stream_data = open_streams[tcp_header->dstport];

    if (tcp_header->ack_seq == (stream_data->last_unacked_seq)) {
        // VALID PACKET ORDERING CHECKED
        switch (stream_data->state) {
            case 0: // EXPECTING SYN-ACK
                if (tcp_header->ack && tcp_header->syn) {
                    stream_data->state+=1;
                    tcp_ack(stream_data, ip_header, tcp_header, sub, tcp_header->seq+1, tcp_header->seq);
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

