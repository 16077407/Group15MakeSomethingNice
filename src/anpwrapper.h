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

#ifndef ANPNETSTACK_ANPWRAPPER_H
#define ANPNETSTACK_ANPWRAPPER_H

#include <sys/socket.h>
#include "tcp.h"

#define TCP_IN_BUFFER_SIZE 10000000000
#define MIN_CUSTOM_TCP_FD 10000000
#define MAX_CUSTOM_TCP_FD 10032000
int LAST_ISSUED_TCP_FD = MIN_CUSTOM_TCP_FD;

void _function_override_init();

struct tcp_stream_info {
	int fd;
	int bytes_tx;
	int bytes_rx;
	int state;
	uint32_t last_seen_seq;
	sockaddr *addrinfo;
	void *rx_in;
	struct tcphdr *header;
};

#endif //ANPNETSTACK_ANPWRAPPER_H
