 /*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the code that manages the ARP cache and
 *  the list of pending ARP requests.
 *
 *  Most importantly, this module defines a function chirouter_arp_process
 *  that is run as a separate thread, and which will wake up every second
 *  to purge stale entries in the ARP cache (entries that are more than 15 seconds
 *  old) and to traverse the list of pending ARP requests. For each pending
 *  request in the list, it will call chirouter_arp_process_pending_req,
 *  which must either re-send the pending ARP request or cancel the
 *  request and send ICMP Host Unreachable messages in reply to all
 *  the withheld frames.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdbool.h>
#include "arp.h"
#include "chirouter.h"
#include "utils.h"
#include "utlist.h"

#define ARP_REQ_KEEP (0)
#define ARP_REQ_REMOVE (1)

#define ICMP_PROTOCOL_CODE (0x01)
#define TCP_PROTOCOL_CODE (0x06)
#define UDP_PROTOCOL_CODE (0x11)

/*additional helper function, description in arp.h*/
ethernet_frame_t* arp_request(uint32_t dst_ip, chirouter_interface_t *iface)
{
    ethernet_frame_t* ret = (ethernet_frame_t*) malloc(sizeof(ethernet_frame_t));
    ethhdr_t* hdr;
    arp_packet_t* arp;
    ret->length = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    ret->raw = (uint8_t*) malloc(ret->length);
    hdr = (ethhdr_t*) ret->raw;
    ret->in_interface = iface;
    memset(hdr->dst, 255, ETHER_ADDR_LEN);
    memset(hdr->src, 0, ETHER_ADDR_LEN);
    memcpy(hdr->src, iface->mac, ETHER_ADDR_LEN);
    hdr->type = htons(ETHERTYPE_ARP);
    arp = (arp_packet_t*) (ret->raw + sizeof(ethhdr_t));
    arp->hrd = htons(ARP_HRD_ETHERNET);
    arp->pro = htons(ETHERTYPE_IP);
    arp->hln = ETHER_ADDR_LEN;
    arp->pln = IPV4_ADDR_LEN;
    arp->op = htons(ARP_OP_REQUEST);
    memcpy(arp->sha, iface->mac, ETHER_ADDR_LEN);
    arp->spa = iface->ip.s_addr;
    memset(arp->tha, 255, ETHER_ADDR_LEN);
    arp->tpa = dst_ip;
    chilog_arp(INFO, arp, LOG_OUTBOUND);
    return ret;
}

/*additional helper function, description in arp.h*/
int icmp_time_exceeded(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    uint32_t send_check, addr;
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* ip_header = (iphdr_t *) (frame->raw + sizeof(ethhdr_t));
    icmp_packet_t* icmp = (icmp_packet_t  *) (frame->raw + sizeof(ethhdr_t) +
                                              sizeof(iphdr_t));
    chirouter_interface_t* interface = frame->in_interface;
    chilog(INFO, "Sending a Time Exceeded Message");
    chilog(INFO, "Initial ICMP Packet");
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    memset(icmp->time_exceeded.payload, 0, sizeof(iphdr_t) + 8);
    memcpy(icmp->time_exceeded.payload, ip_header, sizeof(iphdr_t) + 8);
    icmp->type = ICMPTYPE_TIME_EXCEEDED;
    icmp->code = 0; 
    addr = ip_header->dst;
    ip_header->proto = ICMP_PROTOCOL_CODE;
    ip_header->dst = ip_header->src;
    ip_header->src = addr;
    memset(hdr->dst, 0, ETHER_ADDR_LEN);
    memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
    memset(hdr->src, 0, ETHER_ADDR_LEN);
    memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
    ip_header->ttl = 64;
    ip_header->len = htons(2*sizeof(iphdr_t) + ICMP_HDR_SIZE + 8);
    icmp->chksum = 0;
    icmp->chksum = cksum(icmp, sizeof(iphdr_t) + 8 + ICMP_HDR_SIZE);
    ip_header->cksum = 0;
    ip_header->cksum = cksum(ip_header, sizeof(iphdr_t));
    chilog(INFO, "Sending ICMP Packet");
    chilog_ip(INFO, ip_header, LOG_OUTBOUND);
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    send_check = chirouter_send_frame(ctx, interface, frame->raw, frame->length);
    if (send_check == 0)
        {chilog(INFO, "It works!");}
    return 0;
}

/*additional helper function, description in arp.h*/
int icmp_unreachable(chirouter_ctx_t *ctx, ethernet_frame_t *frame, int type)
{
    uint32_t send_check, addr;
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* ip_header = (iphdr_t *) (frame->raw + sizeof(ethhdr_t));
    icmp_packet_t* icmp = (icmp_packet_t  *) (frame->raw + sizeof(ethhdr_t) +
                           sizeof(iphdr_t));
    chirouter_interface_t* interface = frame->in_interface;
    chilog(INFO, "Sending a Dest Unreachable Message");
    chilog(INFO, "Initial ICMP Packet");
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    memset(icmp->dest_unreachable.payload, 0, sizeof(iphdr_t) + 8);
    memcpy(icmp->dest_unreachable.payload, ip_header, sizeof(iphdr_t) + 8);
    icmp->type = ICMPTYPE_DEST_UNREACHABLE;
    if (type == 0) 
    {icmp->code = ICMPCODE_DEST_NET_UNREACHABLE;}
    else 
    {icmp->code = ICMPCODE_DEST_HOST_UNREACHABLE;}
    addr = ip_header->dst;
    ip_header->proto = ICMP_PROTOCOL_CODE;
    ip_header->len = htons(2*sizeof(iphdr_t) + ICMP_HDR_SIZE + 8);
    ip_header->ttl = 64;
    ip_header->dst = ip_header->src;
    ip_header->src = addr;
    icmp->chksum = 0;
    icmp->chksum = cksum(icmp, sizeof(iphdr_t) + 8 + ICMP_HDR_SIZE);
    ip_header->cksum = 0;
    ip_header->cksum = cksum(ip_header, sizeof(iphdr_t));
    memset(hdr->dst, 0, ETHER_ADDR_LEN);
    memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
    memset(hdr->src, 0, ETHER_ADDR_LEN);
    memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
    chilog(INFO, "Sending ICMP Packet");
    chilog_ip(INFO, ip_header, LOG_OUTBOUND);
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    send_check = chirouter_send_frame(ctx, interface, frame->raw, frame->length);
    if (send_check == 0) 
    {chilog(INFO, "It works!");}
    return 0;
}



/*
 * chirouter_arp_process_pending_req - Process a single pending ARP request
 *
 * Given a pending ARP request, this function will do the following:
 *
 * - If the request has been sent less than five times, re-send the request
 *   (and update the the chirouter_pending_arp_req_t struct to reflect
 *   the number of times the request has been sent) and return ARP_REQ_KEEP
 * - If the request has been sent five times, send an ICMP Host Unreachable
 *   reply for each of the withheld frames and return ARP_REQ_REMOVE
 *
 * ctx: Router context
 *
 * pending_req: Pending ARP request
 *
 * Returns:
 *  - ARP_REQ_KEEP if the ARP request should stay in the pending ARP request list.
 *  - ARP_REQ_REMOVE if the request should be removed from the list.
 */
int chirouter_arp_process_pending_req(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req)
{
    if(pending_req->times_sent == 0)
    {chilog(WARNING, "times_sent = 0, but listed as pending_req!");}
    if(pending_req->times_sent == 5)
    {
        chilog(INFO, "Req sent 5 times, sending ICMP Host Unreachable now");

        struct withheld_frame* elt;
        DL_FOREACH(pending_req->withheld_frames, elt)
        {
            ethernet_frame_t *frame = elt->frame;
            if(!frame)
            {break;}
            icmp_unreachable(ctx, frame, 1);
        }
        
        return ARP_REQ_REMOVE;
    }
    chilog(INFO, "Resending ARP Request");
    chirouter_interface_t* iface = pending_req->out_interface;
    ethernet_frame_t* frame = arp_request(pending_req->ip.s_addr, iface);
    chirouter_send_frame(ctx, iface, frame->raw, frame->length);
    pending_req->times_sent++;

    return ARP_REQ_KEEP;
}
      


/***** DO NOT MODIFY THE CODE BELOW *****/


/* See arp.h */
chirouter_arpcache_entry_t* chirouter_arp_cache_lookup(chirouter_ctx_t *ctx, struct in_addr *ip)
{
    for(int i=0; i < ARPCACHE_SIZE; i++)
    {
        if(ctx->arpcache[i].valid && ctx->arpcache[i].ip.s_addr == ip->s_addr)
        {
            return &ctx->arpcache[i];
        }
    }

    return NULL;
}


/* See arp.h */
int chirouter_arp_cache_add(chirouter_ctx_t *ctx, struct in_addr *ip, uint8_t *mac)
{
    for(int i=0; i < ARPCACHE_SIZE; i++)
    {
        if(!ctx->arpcache[i].valid)
        {
            ctx->arpcache[i].valid = true;
            memcpy(&ctx->arpcache[i].ip, ip, sizeof(struct in_addr));
            memcpy(ctx->arpcache[i].mac, mac, ETHER_ADDR_LEN);
            ctx->arpcache[i].time_added = time(NULL);

            return 0;
        }
    }

    return 1;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_lookup(chirouter_ctx_t *ctx, struct in_addr *ip)
{
    chirouter_pending_arp_req_t *pending_req;
    DL_FOREACH(ctx->pending_arp_reqs, pending_req)
    {
        if(pending_req->ip.s_addr == ip->s_addr)
        {
            return pending_req;
        }
    }

    return NULL;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_add(chirouter_ctx_t *ctx, struct in_addr *ip, chirouter_interface_t *iface)
{
    chirouter_pending_arp_req_t *pending_req = calloc(1, sizeof(chirouter_pending_arp_req_t));

    memcpy(&pending_req->ip, ip, sizeof(struct in_addr));
    pending_req->times_sent = 0;
    pending_req->last_sent = time(NULL);
    pending_req->out_interface = iface;
    pending_req->withheld_frames = NULL;

    DL_APPEND(ctx->pending_arp_reqs, pending_req);

    return pending_req;
}


/* See arp.h */
int chirouter_arp_pending_req_add_frame(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req, ethernet_frame_t *frame)
{
    ethernet_frame_t *frame_copy = calloc(1, sizeof(ethernet_frame_t));

    frame_copy->raw = calloc(1, frame->length);
    memcpy(frame_copy->raw, frame->raw, frame->length);
    frame_copy->length = frame->length;
    frame_copy->in_interface = frame->in_interface;

    withheld_frame_t *withheld_frame = calloc(1, sizeof(withheld_frame_t));
    withheld_frame->frame = frame_copy;

    DL_APPEND(pending_req->withheld_frames, withheld_frame);

    return 0;
}


/* See arp.h */
int chirouter_arp_free_pending_req(chirouter_pending_arp_req_t *pending_req)
{
    withheld_frame_t *withheld_frame, *tmp;
    DL_FOREACH_SAFE(pending_req->withheld_frames, withheld_frame, tmp)
    {
        free(withheld_frame->frame->raw);
        free(withheld_frame->frame);

        DL_DELETE(pending_req->withheld_frames, withheld_frame);
        free(withheld_frame);
    }

    return 0;
}


/* See arp.h */
void* chirouter_arp_process(void *args)
{
    chirouter_ctx_t *ctx = (chirouter_ctx_t *) args;

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(ctx->lock_arp));

        /* Purge the cache */
        time_t curtime = time(NULL);
        for(int i = 0; i < ARPCACHE_SIZE; i++)
        {
            chirouter_arpcache_entry_t *cache_entry = &ctx->arpcache[i];
            double entry_age = difftime(curtime, cache_entry->time_added);

            if ((cache_entry->valid) && (entry_age > ARPCACHE_ENTRY_TIMEOUT)) {
                cache_entry->valid = false;
            }
        }

        /* Process pending ARP requests */
        if (ctx->pending_arp_reqs != NULL)
        {
            chirouter_pending_arp_req_t *pending_req, *tmp;
            DL_FOREACH_SAFE(ctx->pending_arp_reqs, pending_req, tmp)
            {
                int rc;

                rc = chirouter_arp_process_pending_req(ctx, pending_req);

                if(rc == ARP_REQ_REMOVE)
                {
                    chirouter_arp_free_pending_req(pending_req);
                    DL_DELETE(ctx->pending_arp_reqs, pending_req);
                }
            }
       }

        pthread_mutex_unlock(&(ctx->lock_arp));
    }

    return NULL;
}
