/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/types.h>

#include "openflow.h"
#include "ofmsgbuf.h"
#include "agent.h"
#include "flows.h"
#include "meters.h"
#include "groups.h"


#define ALIGN8(x) (x+7)/8*8

extern int current_time;
extern bool rcv_freq;
extern int multi_pos;
extern struct ofmsgbuf *inbuf, *outbuf;
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];
extern int OF_Version;
extern struct ofp_switch_config Switch_config;
extern struct flow_table *flow_table;
extern struct pbuffer *pk_buffer;
extern uint8_t MAC_address[6];

/* Internal functions */
// OpenFlow message handlers
void features_reply13(uint32_t xid);
void set_config13(struct ofp_header * msg);
void config_reply13(uint32_t xid);
void role_reply13(struct ofp_header *msg);

void barrier13_reply(uint32_t xid);

// Mulitpart functions

int multi_aggregate_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_port_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_port_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);

// OpenFlow helper functions
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code);
void clear_buffer(uint8_t buffer_no);
int field_match13(uint8_t *oxm_a, int len_a, uint8_t *oxm_b, int len_b);
static uint32_t match_prereq(uint8_t *oxm, int length);

static inline uint64_t (_htonll)(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}


void of13_message(struct ofp_header *ofph, int size, int count)
{
    struct ofp13_multipart_request *multi_req;
    //fprintf(stderr, "openflow_13.c: OpenFlow message (%u) received type = %d\r\n", htonl(ofph->xid), ofph->type);
    switch(ofph->type)
    {
        case OFPT13_FEATURES_REQUEST:
            rcv_freq = true;
            features_reply13(ofph->xid);
            break;
            
        case OFPT13_SET_CONFIG:
            set_config13(ofph);
            break;
            
        case OFPT13_GET_CONFIG_REQUEST:
            config_reply13(ofph->xid);
            break;
            
        case OFPT13_ROLE_REQUEST:
            role_reply13(ofph);
            break;
            
        case OFPT13_FLOW_MOD:
            flow_mod13(ofph);
            break;
            
        case OFPT13_GROUP_MOD:
            group_mod13(ofph);
            break;
            
        case OFPT13_MULTIPART_REQUEST:
            multi_req  = (struct ofp13_multipart_request *) ofph;
            if ( ntohs(multi_req->type) == OFPMP13_DESC )
            {
                multi_pos += multi_desc_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == 	OFPMP13_FLOW )
            {
                multi_pos += multi_flow_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_AGGREGATE )
            {
                multi_pos += multi_aggregate_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_PORT_STATS )
            {
                multi_pos += multi_port_stats_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_PORT_DESC )
            {
                multi_pos += multi_port_desc_reply13(&shared_buffer[multi_pos], multi_req);
            }

            if ( ntohs(multi_req->type) == OFPMP13_METER )
            {
                multi_pos += multi_meter_stats_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_METER_CONFIG )
            {
                multi_pos += multi_meter_config_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_METER_FEATURES )
            {
                multi_pos += multi_meter_features_reply13(&shared_buffer[multi_pos], multi_req);
            }

            if ( htons(multi_req->type) == OFPMP13_TABLE_FEATURES )
            {
                /**** Floodlight v1.2 crashes when it gets this reply, removed for the moment. *****/
                    // TODO: import multi_tablefeat_reply13 from Zodiac FX
                //multi_pos += multi_tablefeat_reply13(&shared_buffer[multi_pos], multi_req);
                
                // send error message until table features reply is re-implemented
                of_error13(ofph, OFPET13_BAD_REQUEST, OFPBRC13_BAD_TYPE);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_TABLE )
            {
                //multi_pos += multi_table_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_GROUP_FEATURES )
            {
                multi_pos += multi_group_features_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_GROUP_DESC )
            {
                multi_pos += multi_group_desc_reply13(&shared_buffer[multi_pos], multi_req);
            }
            
            if ( ntohs(multi_req->type) == OFPMP13_GROUP )
            {
                multi_pos += multi_group_stats_reply13(&shared_buffer[multi_pos], multi_req);
            }
            break;
            
        case OFPT13_PACKET_OUT:
            packet_out13(ofph);
            break;
            
        case OFPT13_BARRIER_REQUEST:
            barrier13_reply(ofph->xid);
            break;
            
        case OFPT13_METER_MOD:
            meter_mod13(ofph);
            break;
    };
    
    if (size == count && multi_pos !=0)
    {
        msgbuf_push(outbuf, (char *) &shared_buffer, multi_pos);
    }
    return;

}

/*
 *	OpenFlow FEATURE Reply message function
 *
 *	@param xid - transaction ID
 *
 */
void features_reply13(uint32_t xid)
{
    uint64_t datapathid = 0;
    struct ofp13_switch_features features;
    char buf[256];
    features.header.version = OF_Version;
    features.header.type = OFPT13_FEATURES_REPLY;
    features.header.length = htons(sizeof(features));
    features.header.xid = xid;
    memcpy(&datapathid, &MAC_address, 6);
    datapathid = datapathid >> 16;
    features.datapath_id = _htonll(datapathid);
    features.n_buffers = htonl(PACKET_BUFFER);  // Number of packets that can be buffered
    features.n_tables = MAX_TABLES;		// Number of flow tables
    features.capabilities = htonl(OFPC13_FLOW_STATS + OFPC13_TABLE_STATS + OFPC13_PORT_STATS + OFPC13_GROUP_STATS);	// Switch Capabilities
    features.auxiliary_id = 0;	// Primary connection
    
    memcpy(&buf, &features, sizeof(features));
    msgbuf_push(outbuf, (char *) &buf, sizeof(features));
    //fprintf(stderr, "openflow_13.c: Sent Features Reply\n");
    return;
}

/*
 *	OpenFlow SET CONFIG message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void set_config13(struct ofp_header *msg)
{
    struct ofp_switch_config * sc;
    sc = (struct ofp_switch_config *) msg;
    memcpy(&Switch_config, sc, sizeof(&sc));
    return;
}

/*
 *	OpenFlow CONFIG Reply message function
 *
 *	@param xid - transaction ID
 *
 */
void config_reply13(uint32_t xid)
{
    struct ofp13_switch_config cfg_reply;
    cfg_reply.header.version = OF_Version;
    cfg_reply.header.type = OFPT13_GET_CONFIG_REPLY;
    cfg_reply.header.xid = xid;
    cfg_reply.header.length = htons(sizeof(cfg_reply));
    cfg_reply.flags = OFPC13_FRAG_NORMAL;
    cfg_reply.miss_send_len = htons(256);	// Only sending the first 256 bytes
    msgbuf_push(outbuf,(char*)&cfg_reply, sizeof(cfg_reply));
    return;
}

/*
 *	OpenFlow SET CONFIG message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void role_reply13(struct ofp_header *msg)
{
    struct ofp13_role_request role_request;
    memcpy(&role_request, msg, sizeof(struct ofp13_role_request));
    role_request.header.type = OFPT13_ROLE_REPLY;
    role_request.generation_id = 0;
    role_request.role = htonl(OFPCR_ROLE_MASTER);
    msgbuf_push(outbuf, (char*)&role_request, sizeof(struct ofp13_role_request));
    return;
}

/*
 *	OpenFlow Multi-part DESCRIPTION reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    const struct ofp13_desc wx_desc = {
        .mfr_desc = "Northbound Networks",
        .hw_desc  = "Zodiac WX",        
        .sw_desc  = "v1.10 - Build: 20171123_2",
        .serial_num= " ",
        .dp_desc  = "OpenFlow Wireless Access Point"               
    };
    struct ofp13_multipart_reply *reply;
    uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_desc);
    reply = (struct ofp13_multipart_reply *) buffer;
    reply->header.version = OF_Version;
    reply->header.type = OFPT13_MULTIPART_REPLY;
    reply->header.length = htons(len);
    reply->header.xid = msg->header.xid;
    reply->flags = 0;
    reply->type = htons(OFPMP13_DESC);
    memcpy(reply->body, &wx_desc, sizeof(wx_desc));
    return len;
}

/*
 *	OpenFlow Multi-part PORT Description reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_port_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    int numofports = ETH_PORT_NO;
    struct ofp13_multipart_reply *reply;
    struct ofp13_port phys_port[numofports];
    uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(phys_port);
    int j = 0;
    char portname[8];
    reply = (struct ofp13_multipart_reply *) buffer;
    reply->header.version = OF_Version;
    reply->header.type = OFPT13_MULTIPART_REPLY;
    reply->header.length = htons(len);
    reply->header.xid = msg->header.xid;
    reply->flags = 0;
    reply->type = htons(OFPMP13_PORT_DESC);
    
    uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
    
    for(int l=0; l<numofports; l++)
    {
            phys_port[j].port_no = htonl(l+1);
            memset(mac+5,l,1);
            memset(phys_port[j].name, 0, OFP13_MAX_PORT_NAME_LEN);	// Zero out the name string

            if (l == (ETH_PORT_NO-1))
            {
                sprintf(portname, "eth0");
                memcpy(&phys_port[j].hw_addr, MAC_address, 6);
            } else {
                sprintf(portname, "wlan%d",l);
                memcpy(&phys_port[j].hw_addr, mac, sizeof(mac));  
            }

            strcpy(phys_port[j].name, portname);
            phys_port[j].config = 0;
            if (flow_table->port_status[j] == true)
            {
                phys_port[j].state = htonl(OFPPS13_LIVE);
            } else {
                phys_port[j].state = htonl(OFPPS13_LINK_DOWN);
            }
            if (l == numofports-1)
            {
                phys_port[j].curr = htonl(OFPPF13_1GB_HD + OFPPF13_COPPER);
            } else {
                phys_port[j].curr = htonl(OFPPF13_OTHER);
            }
            phys_port[j].advertised = 0;
            phys_port[j].supported = 0;
            phys_port[j].peer = 0;
            phys_port[j].curr_speed = 0;
            phys_port[j].max_speed = 0;
            j ++;
    }
    
    memcpy(reply->body, &phys_port,sizeof(phys_port));
    return len;
}

/*
*   OpenFlow Multi-part AGGREGATE reply message function
*
*   @param *msg - pointer to the OpenFlow message.
*
*/
int multi_aggregate_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{ 
    // Add up the required return values
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    for(int i=0; i<flow_table->iLastFlow; i++)
    {
        if (flow_table->flow_counters[i].active == true)    // Need to add filters, currently includes all flows
        {
            total_bytes += flow_table->flow_counters[i].bytes;
            total_packets += flow_table->flow_counters[i].hitCount;
        }
    }   
    struct ofp13_multipart_reply *reply;
    struct ofp13_aggregate_stats_reply aggregate_reply;
    uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_aggregate_stats_reply);
    reply = (struct ofp13_multipart_reply *) buffer;
    reply->header.version = OF_Version;
    reply->header.type = OFPT13_MULTIPART_REPLY;
    reply->header.xid = msg->header.xid;
    reply->flags = 0;
    reply->type = htons(OFPMP13_AGGREGATE);
    aggregate_reply.packet_count = _htonll(total_packets);
    aggregate_reply.byte_count = _htonll(total_bytes);
    aggregate_reply.flow_count = htonl(flow_table->iLastFlow);
    memcpy(reply->body, &aggregate_reply, sizeof(aggregate_reply));
    reply->header.length = htons(len);
    return len;
}

/*
*   OpenFlow Multi-part PORT Stats reply message function
*
*   @param *msg - pointer to the OpenFlow message.
*
*/
int multi_port_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_port_stats port_stats[ETH_PORT_NO];
    struct ofp13_multipart_reply reply;
    struct ofp13_port_stats_request *port_req = msg->body;
    int stats_size = 0;
    int len = 0;
    uint32_t port = ntohl(port_req->port_no);

    if (port == OFPP13_ANY)
    {
        stats_size = (sizeof(struct ofp13_port_stats) * ETH_PORT_NO);
        len = sizeof(struct ofp13_multipart_reply) + stats_size;

        reply.header.version = OF_Version;
        reply.header.type = OFPT13_MULTIPART_REPLY;
        reply.header.length = htons(len);
        reply.header.xid = msg->header.xid;
        reply.type = htons(OFPMP13_PORT_STATS);
        reply.flags = 0;

        for(int k=0; k<ETH_PORT_NO;k++)
        {
            port_stats[k].port_no = htonl(k+1);
            port_stats[k].rx_packets = _htonll(flow_table->phys13_port_stats[k].rx_packets);
            port_stats[k].tx_packets = _htonll(flow_table->phys13_port_stats[k].tx_packets);
            port_stats[k].rx_bytes = _htonll(flow_table->phys13_port_stats[k].rx_bytes);
            port_stats[k].tx_bytes = _htonll(flow_table->phys13_port_stats[k].tx_bytes);
            port_stats[k].rx_crc_err = _htonll(flow_table->phys13_port_stats[k].rx_crc_err);
            port_stats[k].rx_dropped = _htonll(flow_table->phys13_port_stats[k].rx_dropped);
            port_stats[k].tx_dropped = _htonll(flow_table->phys13_port_stats[k].tx_dropped);
            port_stats[k].rx_frame_err = 0;
            port_stats[k].rx_over_err = 0;
            port_stats[k].tx_errors = 0;
            port_stats[k].rx_errors = 0;
            port_stats[k].collisions = 0;

        }
        memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
        memcpy(buffer+sizeof(struct ofp13_multipart_reply), &port_stats[0], stats_size);
    } else if (port <= OFPP13_MAX) {
        stats_size = sizeof(struct ofp13_port_stats);
        len = sizeof(struct ofp13_multipart_reply) + stats_size;

        reply.header.version = OF_Version;
        reply.header.type = OFPT13_MULTIPART_REPLY;
        reply.header.length = htons(len);
        reply.header.xid = msg->header.xid;
        reply.type = htons(OFPMP13_PORT_STATS);
        reply.flags = 0;

        port_stats[port].port_no = htonl(port);
        port_stats[port].rx_packets = _htonll(flow_table->phys13_port_stats[port-1].rx_packets);
        port_stats[port].tx_packets = _htonll(flow_table->phys13_port_stats[port-1].tx_packets);
        port_stats[port].rx_bytes = _htonll(flow_table->phys13_port_stats[port-1].rx_bytes);
        port_stats[port].tx_bytes = _htonll(flow_table->phys13_port_stats[port-1].tx_bytes);
        port_stats[port].rx_crc_err = _htonll(flow_table->phys13_port_stats[port-1].rx_crc_err);
        port_stats[port].rx_dropped = _htonll(flow_table->phys13_port_stats[port-1].rx_dropped);
        port_stats[port].tx_dropped = _htonll(flow_table->phys13_port_stats[port-1].tx_dropped);
        port_stats[port].rx_frame_err = 0;
        port_stats[port].rx_over_err = 0;
        port_stats[port].tx_errors = 0;
        port_stats[port].rx_errors = 0;
        port_stats[port].collisions = 0;

        memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
        memcpy(buffer+sizeof(struct ofp13_multipart_reply), &port_stats[port], stats_size);
    }
    return len;
}

/*
 *	OpenFlow BARRIER Reply message function
 *
 *	@param xid - transaction ID
 *
 */
void barrier13_reply(uint32_t xid)
{
    //fprintf(stderr, "Sent Barrier reply");
    struct ofp_header of_barrier;
    of_barrier.version= OF_Version;
    of_barrier.length = htons(sizeof(of_barrier));
    of_barrier.type   = OFPT13_BARRIER_REPLY;
    of_barrier.xid = xid;
    msgbuf_push(outbuf, (char*)&of_barrier, sizeof(of_barrier));
    return;
}

/*
 *	OpenFlow PACKET_IN function
 *
 *	@param *buffer - pointer to the buffer containing the packet.
 *	@param ul_size - size of the packet.
 *	@param port - port that the packet was received on.
 *	@param reason - reason for the packet in.
 *
 */
void packet_in13(uint8_t buffer_no, uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, int flow)
{
    uint16_t size = 0;
    struct ofp13_packet_in * pi;
    uint16_t send_size = PACKET_BUFFER_SIZE;
    struct oxm_header13 oxm_header;
    uint32_t in_port = ntohl(port);
    
    pi = (struct ofp13_packet_in *) shared_buffer;
    pi->header.version = OF_Version;
    pi->header.type = OFPT13_PACKET_IN;
    pi->header.xid = 0;
    pi->buffer_id = buffer_no + 100;
    pi->reason = reason;
    pi->table_id = flow_table->flow_match13[flow].table_id;
    pi->cookie = flow_table->flow_match13[flow].cookie;
    
    pi->match.type = htons(OFPMT_OXM);
    pi->match.length = htons(12);
    oxm_header.oxm_class = ntohs(0x8000);
    oxm_header.oxm_field = OFPXMT_OFB_IN_PORT;
    oxm_header.oxm_len = 4;
    memcpy(shared_buffer + sizeof(struct ofp13_packet_in)-4, &oxm_header, 4);
    memcpy(shared_buffer + sizeof(struct ofp13_packet_in), &in_port, 4);
    size = sizeof(struct ofp13_packet_in) + 10 + send_size;
    pi->header.length = htons(size);
    pi->total_len = htons(send_size);
    memcpy(shared_buffer + (size-send_size), buffer, send_size);
    msgbuf_push(outbuf, (char *) &shared_buffer, size);
    pk_buffer->buffer[buffer_no].type = PB_PENDING;  // Mark as sent
    msync(pk_buffer, sizeof(struct pbuffer), MS_ASYNC);
    return;
}

void clear_buffer(uint8_t buffer_no)
{
    pk_buffer->buffer[buffer_no].size = 0;
    pk_buffer->buffer[buffer_no].inport = 0;
    pk_buffer->buffer[buffer_no].reason = 0;
    pk_buffer->buffer[buffer_no].flow = 0;
    memset(&pk_buffer->buffer[buffer_no].buffer, 0, PACKET_BUFFER_SIZE);
    pk_buffer->buffer[buffer_no].type = PB_EMPTY;  // set type last
    return;
}


/*
 *	OpenFlow PACKET_OUT function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */

void packet_out13(struct ofp_header *msg)
{
    int buffer_no = -1;
    struct ofp13_packet_out * po;
    po = (struct ofp13_packet_out *) msg;
    uint32_t inPort = htonl(po->in_port);
    uint8_t *ptr = (uint8_t *) po;
    int size = ntohs(po->header.length) - ((sizeof(struct ofp13_packet_out) + ntohs(po->actions_len)));
    ptr += sizeof(struct ofp13_packet_out) + ntohs(po->actions_len);
    struct ofp13_action_header *act_hdr = po->actions;
    if (ntohs(act_hdr->type) != OFPAT13_OUTPUT) return;
    struct ofp13_action_output *act_out = act_hdr;
    uint32_t outPort = htonl(act_out->port);
    
    if ( po->buffer_id == OFP_NO_BUFFER)
    {
        // Add packet out processing
        return;
    }

    if (po->buffer_id > 99 && po->buffer_id < 133)
    {
        if (pk_buffer->buffer[po->buffer_id - 100].type ==  PB_PENDING)
        {
            pk_buffer->buffer[po->buffer_id - 100].inport = inPort;
            pk_buffer->buffer[po->buffer_id - 100].age = 0;
            pk_buffer->buffer[po->buffer_id - 100].outport = outPort;
            pk_buffer->buffer[po->buffer_id - 100].type = PB_PACKETOUT;  // set type last
            msync(pk_buffer, sizeof(struct pbuffer), MS_ASYNC);
            //printf("openflow13.c: Packet out loaded into buffer %d - port 0x%x (size %d bytes)\n", (po->buffer_id - 100), outPort, pk_buffer->buffer[po->buffer_id - 100].size);
        } else {
            //printf("openflow13.c: Packet buffer %d timed out\n", po->buffer_id - 100);
        }
    }
    return;
}


/*
 *	OpenFlow ERROR message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *	@param - error type.
 *	@param - error code.
 *
 */
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code)
{
    //fprintf(stderr, "openflow_13.c: Sent OF error code %d\r\n", code);
    // get the size of the message, we send up to the first 64 back with the error
    int msglen = htons(msg->length);
    if (msglen > 64) msglen = 64;
    char error_buf[96];
    struct ofp_error_msg error;
    error.header.type = OFPT13_ERROR;
    error.header.version = OF_Version;
    error.header.length = htons(sizeof(struct ofp_error_msg) + msglen);
    error.header.xid = msg->xid;
    error.type = htons(type);
    error.code = htons(code);
    memcpy(error_buf, &error, sizeof(struct ofp_error_msg));
    memcpy(error_buf + sizeof(struct ofp_error_msg), msg, msglen);
    msgbuf_push(outbuf, (char *) &error_buf, (sizeof(struct ofp_error_msg) + msglen));
    return;
}

/*
 *	OpenFlow Port Status message function
 *
 *	@param port - port number that has changed.
 *
 */
void port_status_message13(uint8_t port)
{
    char portname[8];
    uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
    struct ofp13_port_status ofps;
    
    ofps.header.type = OFPT13_PORT_STATUS;
    ofps.header.version = OF_Version;
    ofps.header.length = htons(sizeof(struct ofp13_port_status));
    ofps.header.xid = 0;
    ofps.reason = OFPPR13_MODIFY;
    ofps.desc.port_no = htonl(port+1);
    memset(mac+5,port,1);
    memset(ofps.desc.name, 0, OFP13_MAX_PORT_NAME_LEN);	// Zero out the name string

    if (port == (ETH_PORT_NO-1))
    {
        sprintf(portname, "eth0");
        memcpy(&ofps.desc.hw_addr, MAC_address, 6);
    } else {
        sprintf(portname, "wlan%d",port);
        memcpy(&ofps.desc.hw_addr, mac, sizeof(mac));  
    }

    strcpy(ofps.desc.name, portname);
    ofps.desc.config = 0;
    if (flow_table->port_status[port] == true) ofps.desc.state = htonl(OFPPS13_LIVE);
    if (flow_table->port_status[port] == false) ofps.desc.state = htonl(OFPPS13_LINK_DOWN);
    ofps.desc.curr = htonl(OFPPF13_OTHER);
    ofps.desc.advertised = 0;
    ofps.desc.supported = 0;
    ofps.desc.peer = 0;
    ofps.desc.curr_speed = 0;
    ofps.desc.max_speed = 0;
    msgbuf_push(outbuf, (char *) &ofps, htons(ofps.header.length));
    return;
}


/*
 *	Compares 2 match oxms
 *	Return 1 if a matches for b (b is wider than a)
 *
 *	@param *match_a - pointer to the first match field
 *	@param *match_b - pointer to the second match field
 *
 */
int field_match13(uint8_t *oxm_a, int len_a, uint8_t *oxm_b, int len_b)
{
    if (len_a == 0) {
        return 1;
    }
    uint32_t prereq_a = match_prereq(oxm_a, len_a);
    if (prereq_a & PREREQ_INVALID != 0){
        return 0;
    }
    uint8_t *ahdr = oxm_a;
    while (ahdr < oxm_a + len_a){
        uint32_t afield = ntohl(*(uint32_t*)(ahdr));
        uint8_t *bhdr = oxm_b;
        uint32_t bfield = ntohl(*(uint32_t*)(bhdr));
        while (afield != bfield && bhdr < oxm_b + len_b)
        {
            bhdr += 4 + OXM_LENGTH(bfield);
            bfield = ntohl(*(uint32_t*)(bhdr));
        }
        if (afield != bfield)
        {
            return 0;
        }
        uint16_t eth_type;
        switch(bfield){
            case OXM_OF_ETH_TYPE:
                eth_type = ntohs(*(uint16_t*)(bhdr+4));
                switch (eth_type){
                    case 0x0800:
                        // TODO: ***** check operator precedence
                        if ((prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)) != 0){
                            return 0;
                        }
                        if ((prereq_a & PREREQ_ETH_TYPE_MASK) == PREREQ_IPV6){
                            return 0;
                        }
                        break;
                    case 0x86dd:
                        if ((prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)) != 0){
                            return 0;
                        }
                        if ((prereq_a & PREREQ_ETH_TYPE_MASK) == PREREQ_IPV4){
                            return 0;
                        }
                        break;
                    case 0x0806:
                        if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_ARP) != 0) {
                            return 0;
                        }
                        break;
                    case 0x8847:
                    case 0x8848:
                        if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_MPLS) != 0) {
                            return 0;
                        }
                        break;
                    case 0x88e7:
                        if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_PBB) != 0) {
                            return 0;
                        }
                        break;
                }
                break;
            case OXM_OF_IP_PROTO:
                switch(bhdr[4]){
                    case 1:
                        if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV4) != 0) {
                            return 0;
                        }
                        break;
                    case 6:
                        if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_TCP) != 0) {
                            return 0;
                        }
                        break;
                    case 17:
                        if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_UDP) != 0){
                            return 0;
                        }
                        break;
                    case 58:
                        if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV6) != 0){
                            return 0;
                        }
                        break;
                    case 132:
                        if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_SCTP) != 0){
                            return 0;
                        }
                        break;
                }
                break;
            case OXM_OF_ICMPV6_TYPE:
                switch(bhdr[4]){
                    case 135:
                        if ((prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_SLL) != 0){
                            return 0;
                        }
                        break;
                    case 136:
                        if ((prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_TLL) != 0){
                            return 0;
                        }
                        break;
                }
                break;
        }
        if(OXM_HASMASK(bfield)){
            int length = OXM_LENGTH(bfield)/2;
            if(OXM_HASMASK(afield)){
                for(int i=0; i<length; i++){
                    if ((~ahdr[4+length+i] & bhdr[4+length+i]) != 0){
                        return 0;
                    }
                }
                for(int i=0; i<length; i++){
                    if ((ahdr[4+i] & bhdr[4+length+i]) != bhdr[4+i]){
                        return 0;
                    }
                }
            } else if (memcmp(ahdr+4, bhdr+4, OXM_LENGTH(bfield)) != 0){
                return 0;
            }
        } else if (memcmp(ahdr+4, bhdr+4, OXM_LENGTH(bfield)) != 0){
            uint32_t test = OXM_LENGTH(bfield);
            return 0;
        }
        ahdr += 4 + OXM_LENGTH(afield);
    }
    uint32_t prereq_b = match_prereq(oxm_b, len_b);
    if ((prereq_b & PREREQ_INVALID) != 0){
        return 0;
    }
    if (prereq_a & PREREQ_ETH_TYPE_MASK & ~(prereq_b & PREREQ_ETH_TYPE_MASK) != 0){
        return 0;
    }
    if (prereq_a & PREREQ_ND_MASK & ~(prereq_b & PREREQ_ND_MASK) != 0){
        return 0;
    }
    if ((prereq_b & PREREQ_VLAN) != 0) {
        uint8_t *ahdr = oxm_a;
        while(ahdr < oxm_a + len_a){
            uint32_t afield = *(uint32_t*)(ahdr);
            switch(afield){
                case OXM_OF_VLAN_VID_W:
                    if ((ntohs(*(uint16_t*)(ahdr+6)) & OFPVID_PRESENT) != 0){
                        break;
                    }
                case OXM_OF_VLAN_VID:
                    if (ntohs(*(uint16_t*)(ahdr+4)) == OFPVID_NONE){
                        return 0;
                    }
                    break;
            }
            ahdr += 4 + OXM_LENGTH(afield);
        }
    }
    return 1;
}

static uint32_t match_prereq(uint8_t *oxm, int length)
{
    uint32_t ret = 0;
    uint8_t *hdr = oxm;
    while(hdr < oxm+length){
        uint16_t eth_type;
        uint32_t field = ntohl(*(uint32_t*)(hdr));
        switch(field){
            case OXM_OF_VLAN_PCP:
                ret |= PREREQ_VLAN;
                break;
            case OXM_OF_ETH_TYPE:
                eth_type = ntohl(*(uint16_t*)(hdr+4));
                switch(eth_type){
                        //  TODO: ***** check operator precedence
                    case 0x0800:
                        if ((ret & PREREQ_IP_MASK) == PREREQ_IPV6){
                            ret |= PREREQ_INVALID;
                        }
                        ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
                        break;
                    case 0x86dd:
                        if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                            ret |= PREREQ_INVALID;
                        }
                        ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                        break;
                    case 0x0806:
                        ret |= PREREQ_ARP;
                        break;
                    case 0x8847:
                    case 0x8848:
                        ret |= PREREQ_MPLS;
                        break;
                    case 0x88e7:
                        ret |= PREREQ_PBB;
                        break;
                }
                break;
            case OXM_OF_IP_PROTO:
                switch(hdr[4]){
                    case 1:
                        ret |= PREREQ_ICMPV4;
                        break;
                    case 6:
                        ret |= PREREQ_TCP;
                        break;
                    case 17:
                        ret |= PREREQ_UDP;
                        break;
                    case 58:
                        ret |= PREREQ_ICMPV6;
                        break;
                    case 132:
                        ret |= PREREQ_SCTP;
                        break;
                }
                if ((ret & PREREQ_IP_MASK) == 0 ){
                    ret |= PREREQ_IP_MASK;
                }
                break;
            case OXM_OF_ICMPV6_TYPE:
                switch(hdr[4]){
                    case 135:
                        if ((ret & PREREQ_ND_MASK) == PREREQ_ND_TLL){
                            ret |= PREREQ_INVALID;
                        }
                        ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
                        break;
                    case 136:
                        if ((ret & PREREQ_ND_MASK) == PREREQ_ND_SLL){
                            ret |= PREREQ_INVALID;
                        }
                        ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
                        break;
                }
                ret |= PREREQ_ICMPV6;
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                break;
            case OXM_OF_IP_DSCP:
            case OXM_OF_IP_ECN:
                if ((ret & PREREQ_IP_MASK) == 0 ){
                    ret |= PREREQ_IP_MASK;
                }
                break;
            case OXM_OF_ICMPV4_TYPE:
            case OXM_OF_ICMPV4_CODE:
                ret |= PREREQ_ICMPV4;
            case OXM_OF_IPV4_DST:
            case OXM_OF_IPV4_DST_W:
            case OXM_OF_IPV4_SRC:
            case OXM_OF_IPV4_SRC_W:
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV6){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
                break;
            case OXM_OF_TCP_SRC:
            case OXM_OF_TCP_DST:
                ret |= PREREQ_TCP;
                if ((ret & PREREQ_IP_MASK) == 0 ){
                    ret |= PREREQ_IP_MASK;
                }
                break;
            case OXM_OF_UDP_SRC:
            case OXM_OF_UDP_DST:
                ret |= PREREQ_UDP;
                if ((ret & PREREQ_IP_MASK) == 0 ){
                    ret |= PREREQ_IP_MASK;
                }
                break;
            case OXM_OF_SCTP_SRC:
            case OXM_OF_SCTP_DST:
                ret |= PREREQ_SCTP;
                if ((ret & PREREQ_IP_MASK) == 0 ){
                    ret |= PREREQ_IP_MASK;
                }
                break;
            case OXM_OF_ARP_OP:
            case OXM_OF_ARP_SPA:
            case OXM_OF_ARP_SPA_W:
            case OXM_OF_ARP_TPA:
            case OXM_OF_ARP_TPA_W:
            case OXM_OF_ARP_SHA:
            case OXM_OF_ARP_THA:
                ret |= PREREQ_ARP;
                break;
            case OXM_OF_ICMPV6_CODE:
                ret |= PREREQ_ICMPV6;
            case OXM_OF_IPV6_SRC:
            case OXM_OF_IPV6_SRC_W:
            case OXM_OF_IPV6_DST:
            case OXM_OF_IPV6_DST_W:
            case OXM_OF_IPV6_FLABEL:
            case OXM_OF_IPV6_EXTHDR:
            case OXM_OF_IPV6_EXTHDR_W:
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                break;
            case OXM_OF_IPV6_ND_TARGET:
                if ((ret & PREREQ_ND_MASK) == 0){
                    ret |= PREREQ_ND_MASK;
                }
                ret |= PREREQ_ICMPV6;
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                break;
            case OXM_OF_IPV6_ND_SLL:
                if ((ret & PREREQ_ND_MASK) == PREREQ_ND_TLL){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
                ret |= PREREQ_ICMPV6;
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                break;
            case OXM_OF_IPV6_ND_TLL:
                if ((ret & PREREQ_ND_MASK) == PREREQ_ND_SLL){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
                ret |= PREREQ_ICMPV6;
                if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
                    ret |= PREREQ_INVALID;
                }
                ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
                break;
            case OXM_OF_MPLS_LABEL:
            case OXM_OF_MPLS_BOS:
            case OXM_OF_MPLS_TC:
                ret |= PREREQ_MPLS;
                break;
            case OXM_OF_PBB_ISID:
                ret |= PREREQ_PBB;
                break;
        }
        hdr += 4 + OXM_LENGTH(field);
    }
    uint32_t flags = 0;
    flags = ret & PREREQ_ETH_TYPE_MASK;
    if (flags!=0 && flags!=PREREQ_IPV4 && flags!=PREREQ_IPV6 && flags!=PREREQ_IP_MASK && flags!=PREREQ_ARP && flags!=PREREQ_MPLS && flags!=PREREQ_PBB){
        ret |= PREREQ_INVALID;
    }
    flags = ret & PREREQ_IP_PROTO_MASK;
    if (flags!=0 && flags!=PREREQ_TCP && flags!=PREREQ_UDP && flags!=PREREQ_SCTP && flags!=PREREQ_ICMPV4 && flags!=PREREQ_ICMPV6){
        ret |= PREREQ_INVALID;
    }
    return ret;
}

