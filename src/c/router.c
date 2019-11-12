/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
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

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"


#define ICMP_PROTOCOL_CODE (0x01)
#define TCP_PROTOCOL_CODE (0x06)
#define UDP_PROTOCOL_CODE (0x11)

/* arp_handle_reply: helps process ARP replies
*
*ctx: router context
*
*frame: inbound ethernet frame
*
*return value: void
*/
void arp_handle_reply(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
    chirouter_pending_arp_req_t *req;
    chilog(INFO, "ARP Reply Received");
    struct in_addr *ip_struct;
    ip_struct = (struct in_addr*) malloc(sizeof(struct in_addr));
    ip_struct->s_addr = arp->spa;
    chirouter_arp_cache_add(ctx, ip_struct, arp->sha);
    req = chirouter_arp_pending_req_lookup(ctx, ip_struct);
    if(req)
    {
        struct ethernet_frame *withheld;
        chilog(INFO, "Forwarding Withheld Frames");
        
        struct withheld_frame* elt;
        DL_FOREACH(req->withheld_frames,elt)
        {
            withheld = elt->frame;
            if(!withheld)
            {break;}
        
            ethhdr_t *w_hdr = (ethhdr_t*) withheld->raw;
            memset(w_hdr->dst, 0, ETHER_ADDR_LEN);
            memcpy(w_hdr->dst, arp->sha, ETHER_ADDR_LEN);
            memset(w_hdr->src, 0, ETHER_ADDR_LEN);
            memcpy(w_hdr->src, req->out_interface->mac, ETHER_ADDR_LEN);
            chirouter_send_frame(ctx, req->out_interface, withheld->raw,
                                 withheld->length);
        }
    DL_DELETE(ctx->pending_arp_reqs, req);

    }
    else
    {
        chilog(WARNING, "ARP reply received for address not requested");
    }
}

/* chirouter_process_ARP: helps process ARP requests and replies
*
*ctx: router context
*
*frame: inbound ethernet frame
*
*return value: 0 on success, 1 on error
*/
int chirouter_process_ARP(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
    chirouter_interface_t* interface = frame->in_interface;
    uint32_t addr = arp->tpa; 
    uint32_t interface_addr = interface->ip.s_addr;
    chilog(INFO, "Inbound ARP packet on interface: %s", interface->name);
    chilog(INFO, "Interface ip: 0x%x", interface->ip.s_addr);
    chilog_arp(INFO, arp, LOG_INBOUND);
    if(ntohs(arp->hrd) != ARP_HRD_ETHERNET)
    {
        chilog(INFO, "ARP Different Hardware Type!");
        return 0;
    }
    if((interface_addr) == (addr))
    {
        chilog(INFO, "ARP target address same as interface address");
        switch(ntohs(arp->op))
        {
            case ARP_OP_REQUEST:
            {
                chilog(INFO, "sending ARP reply");
                arp->tpa = arp->spa;
                arp->spa = addr;
                arp->hrd = htons(ARP_HRD_ETHERNET);
                arp->hln = ETHER_ADDR_LEN;
                arp->pln = IPV4_ADDR_LEN;
                memset(arp->tha, 0, ETHER_ADDR_LEN);
                memcpy(arp->tha, arp->sha, ETHER_ADDR_LEN);
                memset(arp->sha, 0, ETHER_ADDR_LEN);
                memcpy(arp->sha, interface->mac, ETHER_ADDR_LEN);
                memset(hdr->dst, 0, ETHER_ADDR_LEN);
                memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
                memset(hdr->src, 0, ETHER_ADDR_LEN);
                memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
                arp->op = htons(2);
                hdr->type = htons(ETHERTYPE_ARP);
                chirouter_send_frame(ctx, interface, frame->raw, 
                                    frame->length);
                return 0;
            }
            case ARP_OP_REPLY:
            {
                arp_handle_reply(ctx, frame);
            }
            default:
            {
                chilog(ERROR, "Unknown ARP code");
                return 1;
            }
        }
    }
    return 0;
}

/*icmp_echo_request: helps process ICMP echo requests
*
*ctx: router context
*
*frame: inbound ethernet frame
*
*return value: void
*/
void icmp_echo_request(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    uint8_t bad_payload[8] = {0,0,0,0,0,0,0,0}; 
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    uint32_t addr;
    iphdr_t* ip_header = (iphdr_t *) (frame->raw + sizeof(ethhdr_t));
    icmp_packet_t* icmp = (icmp_packet_t  *) (frame->raw + sizeof(ethhdr_t) +
                           sizeof(iphdr_t));
    chirouter_interface_t* interface = frame->in_interface;
    chilog(INFO, "Sending an Echo Reply");
    chilog(INFO, "Initial ICMP Packet");
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    icmp->type = ICMPTYPE_ECHO_REPLY;
    icmp->code = 0; 
    icmp->chksum = 0;
    addr = ip_header->dst;
    ip_header->dst = ip_header->src;
    ip_header->src = addr;
    memset(icmp->echo.payload, 0, sizeof(&ip_header) + 8);
    memcpy(icmp->echo.payload, ip_header, sizeof(&ip_header));
    chilog(INFO, "Sending ICMP Packet");
    chilog_ip(INFO, ip_header, LOG_OUTBOUND);
    chilog_icmp(INFO, icmp, LOG_OUTBOUND);
    memcpy(icmp->echo.payload + sizeof(&ip_header), bad_payload, 8);
    memset(hdr->dst, 0, ETHER_ADDR_LEN);
    memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
    memset(hdr->src, 0, ETHER_ADDR_LEN);
    memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
    chirouter_send_frame(ctx, interface, frame->raw, frame->length);
}

/*chirouter_process_ICMP: helps process ICMP procedures
*
*ctx: router context
*
*frame: inbound ethernet frame
*
*return value: 0 on success
*/
int chirouter_process_ICMP(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    uint32_t addr;
    int send_check;
    iphdr_t* ip_header = (iphdr_t *) (frame->raw + sizeof(ethhdr_t));
    icmp_packet_t* icmp = (icmp_packet_t  *) (frame->raw + sizeof(ethhdr_t) +
                                              sizeof(iphdr_t));
    chirouter_interface_t* interface = frame->in_interface;
    chilog_ip(INFO, ip_header, LOG_INBOUND);
    if (interface->ip.s_addr != ip_header->dst)
    {return icmp_unreachable(ctx, frame, 1);}
    if (ip_header->ttl == 1)
    {return icmp_time_exceeded(ctx, frame);}
    if (icmp->type == ICMPTYPE_ECHO_REQUEST)
    {
        icmp_echo_request(ctx, frame);
        return 0;
    }
    if((ip_header->proto == TCP_PROTOCOL_CODE) ||
       (ip_header->proto == UDP_PROTOCOL_CODE))
    {
        chilog(INFO, "Sending a Dest Unreachable Message");
        chilog(INFO, "Initial ICMP Packet");
        chilog_icmp(INFO, icmp, LOG_OUTBOUND);
        memset(icmp->dest_unreachable.payload, 0, sizeof(iphdr_t) + 8);
        memcpy(icmp->dest_unreachable.payload, ip_header, sizeof(iphdr_t) + 8);
        icmp->type = ICMPTYPE_DEST_UNREACHABLE;
        icmp->code = ICMPCODE_DEST_PORT_UNREACHABLE;
        addr = ip_header->dst;
        ip_header->ttl = 64;
        ip_header->proto = ICMP_PROTOCOL_CODE;
        ip_header->len = htons(2*sizeof(iphdr_t) + ICMP_HDR_SIZE + 8);
        ip_header->dst = ip_header->src;
        ip_header->src = addr;
        memset(hdr->dst, 0, ETHER_ADDR_LEN);
        memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
        memset(hdr->src, 0, ETHER_ADDR_LEN);
        memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
        icmp->chksum = 0;
        icmp->chksum = cksum(icmp, sizeof(iphdr_t) + 8 + ICMP_HDR_SIZE);
        ip_header->cksum = 0;
        ip_header->cksum = cksum(ip_header, sizeof(iphdr_t));
        chilog(INFO, "Sending ICMP Packet");
        chilog_ip(INFO, ip_header, LOG_OUTBOUND);
        chilog_icmp(INFO, icmp, LOG_OUTBOUND);
        send_check = chirouter_send_frame(ctx, interface, frame->raw,
                                              frame->length);
        if (send_check == 0)
        {chilog(INFO, "SUCCESS!");}
        chirouter_send_frame(ctx, interface, frame->raw, frame->length);
        return 0;
    }
    return 0;
}


chirouter_interface_t* ip_forward_interface(chirouter_ctx_t *ctx, uint32_t addr)
{
    uint32_t i, mask;
    for(i = 0; i<ctx->num_rtable_entries; i++)
    {
        mask = ctx->routing_table[i].mask.s_addr;
        if((mask & ctx->routing_table[i].interface->ip.s_addr) == (mask & addr))
        {
            chilog(INFO, "Forwarding packet to %s",
                   ctx->routing_table[i].interface->name);
            return ctx->routing_table[i].interface;
        }
    }
    chilog(WARNING, "Cannot route 0x%X anywhere", addr);
    return NULL;
}

/*should_process_ICMP: helps decide if I should forward IP datagrams
*
*ctx: router context
*
*addr: datagram in IP address
*
*return value: 0 if datagram should be sent, 1 if ICMP reply should be 
*considered
*/
int should_process_ICMP(chirouter_ctx_t *ctx, uint32_t addr)
{
    int i;
    for(i = 0; i<ctx->num_interfaces; i++)
    {
        chirouter_interface_t *iface = &(ctx->interfaces[i]);
        uint32_t iface_addr = iface->ip.s_addr;
        chilog(INFO, "Interface %s addr = 0x%x", iface->name, iface_addr);
        chilog(INFO, "IP DST addr = 0x%x", addr);
        if((iface_addr) == (addr))
        {return 1;}
    }
    return 0;
}

/*icmp_echo_request: helps process IC procedures
*
*ctx: router context
*
*frame: inbound ethernet frame
*
*return value: 0 upon success
*/
int chirouter_process_IP(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* ip = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    uint32_t addr = ip->dst;
    if(should_process_ICMP(ctx, addr))
    {
        chilog(INFO, "Processing ICMP");
        return chirouter_process_ICMP(ctx, frame);
    }
    else
    {
        chirouter_interface_t *iface = ip_forward_interface(ctx, addr);
        if(iface)
        {
            ip->ttl--; 
            ip->cksum = 0; 
            ip->cksum = cksum(ip, sizeof(iphdr_t)); 
            chirouter_arpcache_entry_t* entry;
            struct in_addr *ip_struct = (struct in_addr*)
            malloc(sizeof(struct in_addr));
            ip_struct->s_addr = addr; 
            pthread_mutex_lock(&ctx->lock_arp);
            entry = chirouter_arp_cache_lookup(ctx, ip_struct);
            pthread_mutex_unlock(&ctx->lock_arp); 

            if(entry)
            {
                chilog(INFO, "Found MAC address in arp cache.");
                if(ip->ttl == 0)
                {return icmp_time_exceeded(ctx, frame);}
                memset(hdr->src, 0, ETHER_ADDR_LEN);
                memset(hdr->dst, 0, ETHER_ADDR_LEN);
                memcpy(hdr->dst, entry->mac, ETHER_ADDR_LEN);
                memcpy(hdr->src, iface->mac, ETHER_ADDR_LEN);
                chirouter_send_frame(ctx, iface, frame->raw, frame->length);
            }
            else
            {
                chilog(INFO, "Did not find MAC");
                if(ip->ttl == 0)
                {return icmp_unreachable(ctx, frame, 0);}
                chirouter_pending_arp_req_t* req;
                pthread_mutex_lock(&ctx->lock_arp);
                req = chirouter_arp_pending_req_lookup(ctx, ip_struct);
                if(req)
                {
                    chilog(INFO, "pending arp");
                    chirouter_arp_pending_req_add_frame(ctx, req, frame);
                }
                else
                {
                    chilog(INFO, "Sending ARP request to %s", iface->name);
                    ethernet_frame_t* arp_eth_frame;
                    req = chirouter_arp_pending_req_add(ctx, ip_struct, iface);
                    arp_eth_frame = arp_request(addr, iface);
                    chirouter_send_frame(ctx, iface, arp_eth_frame->raw,
                                             arp_eth_frame->length);
                    req->times_sent = 1;
                    chirouter_arp_pending_req_add_frame(ctx, req, frame);
                }
                pthread_mutex_unlock(&ctx->lock_arp);
            }
        }
        else
        {return icmp_unreachable(ctx, frame, 0);}
        return 0;
    }
}
    
        

/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame. 
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    uint16_t type = ntohs(hdr->type);
    switch (type)
    {
        case ETHERTYPE_ARP:
        {
            chilog(INFO, "Inbound ETHERTYPE_ARP");
            return chirouter_process_ARP(ctx, frame);
        }
        case ETHERTYPE_IP:
        {
            chilog(INFO, "Inbound ETHERTYPE_ARP");
            return chirouter_process_IP(ctx, frame);
        }
        case ETHERTYPE_IPV6:
        {
            chilog(INFO, "ETHERTYPE_IPV6");
            break;
        }
        default:
        {
            chilog(ERROR, "UNKNOWN ETHERTYPE");
            return 1;
        }
    }
    return 0;
}




