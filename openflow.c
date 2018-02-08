/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "agent.h"
#include "openflow.h"
#include "openflow13.h"
#include "ofmsgbuf.h"

extern int sock;
extern struct ofmsgbuf * inbuf, * outbuf;
extern struct shared_mem *shared_mem;
extern struct flow_table *flow_table;
extern int current_time;
extern int last_port_status[ETH_PORT_NO];

int multi_pos;
int OF_Version = 0x04;
bool rcv_freq;
uint8_t shared_buffer[SHARED_BUFFER_LEN];
struct ofp_switch_config Switch_config;


// Internal Functions
void OF_hello(void);
void echo_reply(uint32_t xid);
void echo_request(void);



/********************************************************************************/
void openflowswitch_handle_read()
{
    struct ofp_header *ofph;
    int size = 0;
    int plen = 0;
    int bmin = 0;
    
    int count = msgbuf_read(inbuf, sock);
    if (count <= 0)
    {
        sock = NULL;
    }
    
    while (count > size)
    {
        ofph = msgbuf_peek(inbuf);
        if(msgbuf_count_buffered(inbuf) < ntohs(ofph->length)) return;
        bmin = msgbuf_pull(inbuf, NULL, ntohs(ofph->length));
        if (size == 0) multi_pos = 0;
        if (ofph->length == 0 || ofph->version == 0){
            return;	//Not an OpenFlow packet
        }
        plen = htons(ofph->length);
        
        size = size + plen;

        //printf("openflow.c: Processing %d byte OpenFlow message %u (bmin:%d - count:%d - size:%d - buffer:%d)\r\n", plen, htonl(ofph->xid), bmin, count, size, msgbuf_count_buffered(inbuf));
        
        switch(ofph->type)
        {
            case OFPT13_HELLO:
                if (ofph->version == 4)
                {
                    OF_Version = 4;
                    clear_flowtable();
                } else {
                    OF_Version = 4;
                }
                break;
            case OFPT13_ECHO_REQUEST:
                echo_reply(ofph->xid);
                break;
                
            default:
                if (OF_Version == 0x04) of13_message(ofph, size, count);
                
        };
    }
    //printf("openflow.c: Processing finished buffer:%d)\r\n", msgbuf_count_buffered(inbuf));
}

static void openflowswitch_handle_write()
{
    // send any data if it's queued
    if( msgbuf_count_buffered(outbuf) > 0) msgbuf_write(outbuf, sock, 0);
}

void openflowswitch_handle_io(const struct pollfd *pfd)
{
    if(pfd->revents & POLLIN) openflowswitch_handle_read();
    if(pfd->revents & POLLOUT) openflowswitch_handle_write();
}
/********************************************************************************/


/*
 *	OpenFlow HELLO message function
 *
 */
void OF_hello(void)
{
    struct ofp_header ofph;
    
    ofph.version = OF_Version;
    ofph.type = OFPT13_HELLO;
    ofph.length = htons(sizeof(ofph));
    ofph.xid = htonl(1);
    msgbuf_push(outbuf,(char * ) &ofph, sizeof(ofph));
    return;
}

/*
 *	OpenFlow ECHO Reply message function
 *
 *	@param xid - transaction ID
 *
 */
void echo_reply(uint32_t xid)
{
    struct ofp_header echo;
    echo.version = OF_Version;
    echo.length = htons(sizeof(echo));
    echo.type   = OFPT13_ECHO_REPLY;
    echo.xid = xid;
    //fprintf(stderr, "openflow.c: Sent ECHO reply\r\n");
    msgbuf_push(outbuf,(char * ) &echo, sizeof(echo));
    return;
}

/*
 *	OpenFlow ECHO Request message function
 *
 */
void echo_request(void)
{
    struct ofp_header echo;
    echo.version= OF_Version;
    echo.length = htons(sizeof(echo));
    echo.type   = OFPT13_ECHO_REQUEST;
    echo.xid = 1234;
    //fprintf(stderr, "openflow.c: Sent ECHO request\r\n");
    msgbuf_push(outbuf,(char * ) &echo, sizeof(echo));
    return;
}

/*
 *	OpenFlow housekeeping timer function
 *
 */
void of_timer(void)
{
    int x = 0;
    // Update time counter
    current_time = (int)time(NULL);
    
    // Check for flow timeouts
    flow_timeouts();

    // Update port status
    for (x=0;x<ETH_PORT_NO;x++)
    {
        if (last_port_status[x] != flow_table->port_status[x])
        {
            last_port_status[x] = flow_table->port_status[x];
            port_status_message13(x);
        }
    }
    return;
}

/*
 *	Flow timeout processing function
 *
 */
void flow_timeouts(void)
{
    // Loop through flow table
    for (int i=0;i<flow_table->iLastFlow;i++)
    {
        // Check if flow is active
        if (flow_table->flow_counters[i].active == true)
        {
            // Check idle timeouts and hard timeouts
            if (flow_table->flow_match13[i].idle_timeout != 0
                    && flow_table->flow_counters[i].lastmatch > 0
                    && (current_time - flow_table->flow_counters[i].lastmatch)
                        >= ntohs(flow_table->flow_match13[i].idle_timeout))
            {
                // Check if "flow removed" message needs to be sent
                if ((ntohs(flow_table->flow_match13[i].flags)
                    &  OFPFF13_SEND_FLOW_REM) == OFPFF13_SEND_FLOW_REM)
                {
                    flowrem_notif13(i,OFPRR13_IDLE_TIMEOUT);
                }
                // Flow has timed out
                remove_flow13(i);
                return;
            }
            else if (flow_table->flow_match13[i].hard_timeout != 0
                    && (current_time - flow_table->flow_counters[i].duration)
                        >= ntohs(flow_table->flow_match13[i].hard_timeout))
            {
                // Check if "flow removed" message needs to be sent
                if ((ntohs(flow_table->flow_match13[i].flags)
                    &  OFPFF13_SEND_FLOW_REM) == OFPFF13_SEND_FLOW_REM)
                {
                    flowrem_notif13(i,OFPRR13_HARD_TIMEOUT);
                }
                // Flow has timed out
                remove_flow13(i);
                return;
            }
        }
    }
    return;
}
