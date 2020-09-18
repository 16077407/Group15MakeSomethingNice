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

#include "icmp.h"
#include "ip.h"
#include "utilities.h"
#include "arpa/inet.h"

void icmp_rx(struct subuff *sub){
    //FIXME: implement your ICMP packet processing implementation here
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)
    struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);;
    struct icmp *icmp = (struct icmp *) ip_header->data;
    if (icmp->type == ICMP_V4_ECHO) {
      icmp_reply(sub);
      return;
    }
    printf("%s\n", "ICMP did not receive supported type");
    free_sub(sub);
}

void icmp_reply(struct subuff *sub){
    //FIXME: implement your ICMP reply implementation here
    // preapre an ICMP response buffer
    // send it out on ip_ouput(...)
    struct iphdr *ip_header = (struct iphdr *)(sub->head + ETH_HDR_LEN);
    struct icmp *icmp;

    uint16_t icmp_len = ip_header->len - (ip_header->ihl * 4);

    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + icmp_len);
    sub_push(sub, icmp_len);

    icmp = (struct icmp *)sub->data;

    icmp->type = ICMP_V4_REPLY;
    icmp->checksum = 0;
    icmp->checksum = do_csum(icmp, icmp_len, 0);

    sub->protocol = IPP_NUM_ICMP;

    ip_output(ip_header->saddr, sub);
    free_sub(sub);
}
