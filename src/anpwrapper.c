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

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "tcp.h"


void *open_streams[1<<16-1];

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

				open_streams[stream->header->srcport] = stream; // Store for later

				// Return useful FD
				LAST_ISSUED_TCP_FD += 1;
				stream->fd = LAST_ISSUED_TCP_FD;

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

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = MAX_CUSTOM_TCP_FD>sockfd>MIN_CUSTOM_TCP_FD;
    if(is_anp_sockfd){
				// 1. Send Initial SYN packet
				//	- put packet on wire with correct headers (set a random seq)
				//	- increment state
				// 2. Recv SYN-ACK
				//  - recieve packet, check if relevant to this handshake (seq+=1 ack=initial seq)
				//    - if relevant increment state
				// 3. Send ACK
				//  - Send ACK for SYN-ACK (seq=last seq +1 ack=initial random seq +1)
				//  - Increment state

        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// ANP Milestone 3
int tcp_rx(struct subuff *sub){
  struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
  struct tcphdr *tcp_header = (struct tcphdr *) ip_header->data;
	struct tcp_stream_info *stream_data = open_streams[tcp_header->dstport];

	if (tcp_header->ack_seq == (stream_data->last_unacked_seq)) {
   	// VALID PACKET ORDERING
		switch (stream_data->state) {
			case 0: // error, this stream has not had connect called yet
				return 0;
			default:
				return -1;
		}
    return 0;
  }
  printf("%s\n", "TCP SYN ACK was not correct");
  free_sub(sub);
}

int tcp_tx(){

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
