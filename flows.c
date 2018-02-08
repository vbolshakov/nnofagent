//
//  flows.c
//  nnofagent
//
//  Created by Paul Zanna on 26/8/17.
//  Copyright © 2017 Northbound Networks. All rights reserved.
//

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
#include "flows.h"

extern struct flow_table *flow_table;
extern int current_time;
extern int OF_Version;
extern struct ofmsgbuf *inbuf, *outbuf;

#define ALIGN8(x) (x+7)/8*8

static inline uint64_t (_htonll)(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

/*
 *	Main OpenFlow FLOW_MOD message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void flow_mod13(struct ofp_header *msg)
{
    struct ofp13_flow_mod * ptr_fm;
    ptr_fm = (struct ofp13_flow_mod *) msg;
    
    switch(ptr_fm->command)
    {
        case OFPFC13_ADD:
            flow_add13(msg);
            break;
            
        case OFPFC13_MODIFY:
            //flow_modify13(msg);
            break;
            
        case OFPFC13_MODIFY_STRICT:
            //flow_modify_strict13(msg);
            break;
            
        case OFPFC13_DELETE:
            flow_delete13(msg);
            break;
            
        case OFPFC13_DELETE_STRICT:
            flow_delete_strict13(msg);
            break;
    }
    return;
}

/*
 *	OpenFlow FLOW_ADD function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void flow_add13(struct ofp_header *msg)
{
    // Return an error if tables are full
    if (flow_table->iLastFlow > (MAX_FLOWS_13-1))
    {
        of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
        return;
    }
    struct ofp13_flow_mod * ptr_fm;
    ptr_fm = (struct ofp13_flow_mod *) msg;
    // Tables are numbered from 0 to (MAX_TABLES-1). If higher then (MAX_TABLES-1) return bad table error
    if (ptr_fm->table_id > (MAX_TABLES-1))
    {
        of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
        return;
    }
    
    // Check for an existing flow the same
    struct flows_counter flow_count_old;
    for(int q=0;q<flow_table->iLastFlow;q++)
    {
        if(flow_table->ofp13_oxm[q].match_size == 0)
        {
            if((memcmp(flow_table->flow_match13[q].match.oxm_fields, ptr_fm->match.oxm_fields, 4) == 0) && (flow_table->flow_match13[q].priority == ptr_fm->priority) && (flow_table->flow_match13[q].table_id == ptr_fm->table_id))
            {
                // Check for overlap flag
                if (ntohs(ptr_fm->flags) &  OFPFF13_CHECK_OVERLAP)
                {
                    of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
                    return;
                }
                // Check if we need to reset the counters
                if (ntohs(ptr_fm->flags) &  OFPFF13_RESET_COUNTS)
                {
                    remove_flow13(q);	// remove the matching flow
                }
                else
                {
                    //fprintf(stderr, "openflow_13.c: Replacing flow %d\r\n", q+1);
                    memcpy(&flow_count_old, &flow_table->flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
                    remove_flow13(q);	// remove the matching flow
                    memcpy(&flow_table->flow_counters[flow_table->iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
                    flow_table->flow_counters[flow_table->iLastFlow].duration = 0;
                }
            }
        }
        else
        {
            if((memcmp(flow_table->ofp13_oxm[q].match, ptr_fm->match.oxm_fields, ntohs(flow_table->flow_match13[q].match.length)-4) == 0) && (flow_table->flow_match13[q].priority == ptr_fm->priority) && (flow_table->flow_match13[q].table_id == ptr_fm->table_id))
            {
                if (ntohs(ptr_fm->flags) &  OFPFF13_CHECK_OVERLAP)
                {
                    of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
                    return;
                }
                // Check if we need to reset the counters
                if (ntohs(ptr_fm->flags) &  OFPFF13_RESET_COUNTS)
                {
                    remove_flow13(q);	// remove the matching flow
                }
                else
                {
                    //fprintf(stderr, "openflow_13.c: Replacing flow %d\r\n", q+1);
                    memcpy(&flow_count_old, &flow_table->flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
                    remove_flow13(q);	// remove the matching flow
                    memcpy(&flow_table->flow_counters[flow_table->iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
                    flow_table->flow_counters[flow_table->iLastFlow].duration = 0;
                }
            }
        }
    }
    
    
    memcpy(&flow_table->flow_match13[flow_table->iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
    
    // Allocate a space to store match fields
    if (ntohs(ptr_fm->match.length) > 4)
    {
        flow_table->ofp13_oxm[flow_table->iLastFlow].match_size = ntohs(flow_table->flow_match13[flow_table->iLastFlow].match.length)-4;
        
        //fprintf(stderr, "openflow_13.c: Allocating %d bytes at %p for match field in flow %d\r\n", ntohs(flow_table->flow_match13[flow_table->iLastFlow].match.length)-4, flow_table->ofp13_oxm[flow_table->iLastFlow].match, flow_table->iLastFlow+1);
        
        memcpy(flow_table->ofp13_oxm[flow_table->iLastFlow].match, ptr_fm->match.oxm_fields, ntohs(flow_table->flow_match13[flow_table->iLastFlow].match.length)-4);
    }
    else
    {
        flow_table->ofp13_oxm[flow_table->iLastFlow].match_size = 0;
    }
    
    // Allocate a space to store instructions and actions
    int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
    //printf("openflow_13.c: mod_size = %d bytes - match len = %d\r\n", mod_size, ntohs(ptr_fm->match.length));
    int instruction_size = ntohs(ptr_fm->header.length) - mod_size;
    if (instruction_size > 1099) 
    {
        of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
        return; 
    }
    //printf("openflow_13.c: instruction_size = %d bytes\r\n", instruction_size);
    if (instruction_size > 0)
    {
        flow_table->ofp13_oxm[flow_table->iLastFlow].inst_size = instruction_size;
        //printf("openflow_13.c: Copying %d bytes at %p for instruction field in flow %d\r\n", instruction_size, flow_table->ofp13_oxm[flow_table->iLastFlow].inst, flow_table->iLastFlow+1);
        uint8_t *inst_ptr = (uint8_t *)ptr_fm + mod_size;
        memcpy(&flow_table->ofp13_oxm[flow_table->iLastFlow].inst, inst_ptr, instruction_size);
    }
    else
    {
        flow_table->ofp13_oxm[flow_table->iLastFlow].inst_size = 0;
    }
    
    flow_table->ofp13_oxm[flow_table->iLastFlow].inst_size = instruction_size;
    flow_table->flow_counters[flow_table->iLastFlow].duration = current_time;
    flow_table->flow_counters[flow_table->iLastFlow].lastmatch = current_time;
    flow_table->flow_counters[flow_table->iLastFlow].active = true;
    //fprintf(stderr, "openflow_13.c: New flow added at %d into table %d : priority %d\r\n", flow_table->iLastFlow+1, ptr_fm->table_id, ntohs(ptr_fm->priority));
    flow_table->iLastFlow++;
    //fprintf("openflow_13.c: iLastFlow = 0x%x = %d\n", &flow_table->iLastFlow, flow_table->iLastFlow);
    msync(flow_table, sizeof(struct flow_table), MS_ASYNC);
    return;
}

/*
 *  Remove flow entry function
 *  Removes a flow entry from the flow table
 *
 *	@param flow_id - the index number of the flow to remove
 *
 */
void remove_flow13(int flow_id)
{
    // Clear the match and instruction entries for the specified flow
    flow_table->ofp13_oxm[flow_id] = (const struct ofp13_oxm){0};
    // Clear the flow entry
    flow_table->flow_match13[flow_id] = (const struct ofp13_flow_mod){0};
    // Clear the flow counters
    flow_table->flow_counters[flow_id] = (const struct flows_counter){0};
    
    // Check if the removed flow was the final flow
    if(flow_id != (flow_table->iLastFlow)-1)
    {
        /* Copy the final flow entry to fill the gap of the removed flow */
        
        // Copy flow entry
        memcpy(&(flow_table->flow_match13[flow_id]),
               &(flow_table->flow_match13[(flow_table->iLastFlow)-1]),
               sizeof(struct ofp13_flow_mod));
        // Copy actions and instructions (with sizes)
        memcpy(&(flow_table->ofp13_oxm[flow_id]),
               &(flow_table->ofp13_oxm[(flow_table->iLastFlow)-1]),
               sizeof(struct ofp13_oxm));
        // Copy counters
        memcpy(&(flow_table->flow_counters[flow_id]),
               &(flow_table->flow_counters[(flow_table->iLastFlow)-1]),
               sizeof(struct flows_counter));
        
        // Clear the match and instruction entries for the last flow
        flow_table->ofp13_oxm[(flow_table->iLastFlow)-1] = (const struct ofp13_oxm){0};
        // Clear the flow entry
        flow_table->flow_match13[(flow_table->iLastFlow)-1] = (const struct ofp13_flow_mod){0};
        // Clear the flow counters
        flow_table->flow_counters[(flow_table->iLastFlow)-1] = (const struct flows_counter){0};
        
    }
    
    // Decrement flow count
    (flow_table->iLastFlow)--;
    
    return;
}

void flow_delete13(struct ofp_header *msg)
{
    struct ofp13_flow_mod *ptr_fm;
    ptr_fm = (struct ofp13_flow_mod*) msg;
    
    //fprintf(stderr, "openflow_13.c: Flow mod DELETE received");
    
    for(int q=0;q<flow_table->iLastFlow;q++)
    {
        if(flow_table->flow_counters[q].active == false)
        {
            // Skip if entry is empty
            continue;
        }
        if (ptr_fm->table_id != OFPTT_ALL && ptr_fm->table_id != flow_table->flow_match13[q].table_id)
        {
            // Skip if table id does not match
            continue;
        }
        if (ptr_fm->cookie_mask != 0 && ptr_fm->cookie != (flow_table->flow_match13[q].cookie & ptr_fm->cookie_mask))
        {
            // Skip on filter cookie value
            continue;
        }
        if (ptr_fm->out_port != OFPP13_ANY)
        {
            bool out_port_match = false;
            int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
            int instruction_size = ntohs(flow_table->flow_match13[q].header.length) - mod_size;       // TODO: check, remove
            struct ofp13_instruction *inst;
            // TODO: check end address
            for(inst=&(flow_table->ofp13_oxm[q].inst); inst<&(flow_table->ofp13_oxm[q].inst)+instruction_size; inst+=inst->len)
            {
                if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
                {
                    struct ofp13_instruction_actions *ia = inst;
                    struct ofp13_action_header *action;
                    for(action=ia->actions; action<inst+inst->len; action+=action->len)
                    {
                        if(action->type==OFPAT13_OUTPUT)
                        {
                            struct ofp13_action_output *output = action;
                            if (output->port == ptr_fm->out_port)
                            {
                                out_port_match = true;
                            }
                            
                        }
                    }
                }
            }
            
            if(out_port_match==false)
            {
                continue;
            }
        }
        if (ptr_fm->out_group != OFPG13_ANY)
        {
            bool out_group_match = false;
            int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
            int instruction_size = ntohs(flow_table->flow_match13[q].header.length) - mod_size;          // TODO: check, remove
            struct ofp13_instruction *inst;
            // TODO: check end address
            for(inst=&(flow_table->ofp13_oxm[q].inst); inst<&(flow_table->ofp13_oxm[q].inst)+instruction_size; inst+=inst->len)
            {
                if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
                {
                    struct ofp13_instruction_actions *ia = inst;
                    struct ofp13_action_header *action;
                    for(action=ia->actions; action<inst+inst->len; action+=action->len)
                    {
                        if(action->type==OFPAT13_GROUP)
                        {
                            struct ofp13_action_group *group = action;
                            if (group->group_id == ptr_fm->out_group)
                            {
                                out_group_match = true;
                            }
                        }
                    }
                }
            }
            if(out_group_match==false)
            {
                continue;
            }
        }
        
        if(field_match13(ptr_fm->match.oxm_fields, ntohs(ptr_fm->match.length)-4, flow_table->ofp13_oxm[q].match, ntohs(flow_table->flow_match13[q].match.length)-4) == 0)
        {
            continue;
        }
        
        if (ntohs(ptr_fm->flags) & OFPFF13_SEND_FLOW_REM
            || ntohs(flow_table->flow_match13[q].flags) &  OFPFF13_SEND_FLOW_REM)
        {
            flowrem_notif13(q,OFPRR13_DELETE);
        }
        
        // Remove the flow entry
        //fprintf(stderr, "openflow_13.c: Flow %d removed", q+1);
        remove_flow13(q);
        
        // Index assignment adjusted by remove_flow13
        q--;
    }
    return;
}

void flow_delete_strict13(struct ofp_header *msg)
{
    struct ofp13_flow_mod *ptr_fm = msg;
    //fprintf(stderr, "openflow_13.c: Flow mod DELETE STRICT received");
    for(int q=0;q<flow_table->iLastFlow;q++)
    {
        // Check if the flow is active
        if(flow_table->flow_counters[q].active == false)
        {
            continue;
        }
        // Check if it is the correct flow table
        if (ptr_fm->table_id != OFPTT_ALL && ptr_fm->table_id != flow_table->flow_match13[q].table_id)
        {
            continue;
        }
        // Check if the priority is the same
        if (ptr_fm->priority != flow_table->flow_match13[q].priority)
        {
            continue;
        }
        // Check if the cookie values are the same
        if (ptr_fm->cookie_mask != 0 && ptr_fm->cookie != flow_table->flow_match13[q].cookie & ptr_fm->cookie_mask)
        {
            continue;
        }
        
        if (ptr_fm->out_port != OFPP13_ANY)
        {
            bool out_port_match = false;
            int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
            int instruction_size = ntohs(flow_table->flow_match13[q].header.length) - mod_size;
            struct ofp13_instruction *inst;
            // TODO: check end address
            for(inst=&(flow_table->ofp13_oxm[q].inst); inst<&(flow_table->ofp13_oxm[q].inst)+instruction_size; inst+=inst->len)
            {
                if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
                {
                    struct ofp13_instruction_actions *ia = inst;
                    struct ofp13_action_header *action;
                    for(action=ia->actions; action<inst+inst->len; action+=action->len)
                    {
                        if(action->type==OFPAT13_OUTPUT)
                        {
                            struct ofp13_action_output *output = action;
                            if (output->port == ptr_fm->out_port)
                            {
                                out_port_match = true;
                            }
                        }
                    }
                }
            }
            
            if(out_port_match == false)
            {
                continue;
            }
        }
        if (ptr_fm->out_group != OFPG13_ANY)
        {
            bool out_group_match = false;
            int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
            int instruction_size = ntohs(flow_table->flow_match13[q].header.length) - mod_size;
            struct ofp13_instruction *inst;
            // TODO: check end address
            for(inst=&(flow_table->ofp13_oxm[q].inst); inst<&(flow_table->ofp13_oxm[q].inst)+instruction_size; inst+=inst->len)
            {
                if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
                {
                    struct ofp13_instruction_actions *ia = inst;
                    struct ofp13_action_header *action;
                    for(action=ia->actions; action<inst+inst->len; action+=action->len)
                    {
                        if(action->type==OFPAT13_GROUP)
                        {
                            struct ofp13_action_group *group = action;
                            if (group->group_id == ptr_fm->out_group)
                            {
                                out_group_match = true;
                            }
                        }
                    }
                }
            }
            if(out_group_match==false)
            {
                continue;
            }
        }
        
        if(flow_table->ofp13_oxm[q].match == NULL)
        {
            if(memcmp(flow_table->flow_match13[q].match.oxm_fields, ptr_fm->match.oxm_fields, 4) != 0)
            {
                continue;
            }
        } else
        {
            if(memcmp(flow_table->ofp13_oxm[q].match, ptr_fm->match.oxm_fields, ntohs(flow_table->flow_match13[q].match.length)-4) != 0)
            {
                continue;
            }
        }
        
        if (ntohs(ptr_fm->flags) & OFPFF13_SEND_FLOW_REM || ntohs(flow_table->flow_match13[q].flags) &  OFPFF13_SEND_FLOW_REM) flowrem_notif13(q,OFPRR13_DELETE);
        //fprintf(stderr, "openflow_13.c: Flow %d removed", q+1);
        // Remove the flow entry
        remove_flow13(q);
        q--;
    }
    return;
}

/*
 *	OpenFlow FLOW Removed message function
 *
 *	@param flowid - flow number.
 *	@param reason - the reason the flow was removed.
 *
 */
void flowrem_notif13(int flowid, uint8_t reason)
{
    struct ofp13_flow_removed ofr;
    double diff;
    char flow_rem[128];
    
    ofr.header.type = OFPT13_FLOW_REMOVED;
    ofr.header.version = OF_Version;
    ofr.header.length = htons((sizeof(struct ofp13_flow_removed)-4) + ntohs(flow_table->flow_match13[flowid].match.length));
    ofr.header.xid = 0;
    ofr.cookie = flow_table->flow_match13[flowid].cookie;
    ofr.reason = reason;
    ofr.priority = flow_table->flow_match13[flowid].priority;
    diff = current_time - flow_table->flow_counters[flowid].duration;
    ofr.duration_sec = htonl(diff);
    ofr.duration_nsec = 0;
    ofr.packet_count = _htonll(flow_table->flow_counters[flowid].hitCount);
    ofr.byte_count = _htonll(flow_table->flow_counters[flowid].bytes);
    ofr.idle_timeout = flow_table->flow_match13[flowid].idle_timeout;
    ofr.hard_timeout = flow_table->flow_match13[flowid].hard_timeout;
    ofr.table_id = flow_table->flow_match13[flowid].table_id;
    memcpy(&ofr.match, &(flow_table->flow_match13[flowid].match), sizeof(struct ofp13_match));
    memcpy(flow_rem, &ofr, sizeof(struct ofp13_flow_removed));
    if (ntohs(flow_table->flow_match13[flowid].match.length) > 4)
    {
        memcpy(flow_rem + (sizeof(struct ofp13_flow_removed)-4), flow_table->ofp13_oxm[flowid].match, ntohs(flow_table->flow_match13[flowid].match.length)-4);
    }
    msgbuf_push(outbuf,(char*)&flow_rem, htons(ofr.header.length)-4);
    return;
}

/*
 *	OpenFlow Multi-part FLOW reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    int len = 0;
    char statsbuffer[16384];
    struct ofp13_multipart_reply *reply;
    reply = (struct ofp13_multipart_reply *) buffer;
    reply->header.version = OF_Version;
    reply->header.type = OFPT13_MULTIPART_REPLY;
    reply->header.xid = msg->header.xid;
    reply->flags = 0;
    reply->type = htons(OFPMP13_FLOW);
    
    // Send all flows
    len = flow_stats_msg13(&statsbuffer, 0, flow_table->iLastFlow);
    
    memcpy(reply->body, &statsbuffer, len);
    len += 	sizeof(struct ofp13_multipart_reply);
    reply->header.length = htons(len);
    return len;
}

/*
 *	Builds the body of a flow stats request for OF 1.3
 *
 *	@param *buffer- pointer to the buffer to store the response
 *	@param *first - first flow to include
 *	@param *last - last flow to include
 *
 */
int flow_stats_msg13(char *buffer, int first, int last)
{
    struct ofp13_flow_stats flow_stats;
    char *buffer_ptr = buffer;
    int len;
    
    for(int k = first; k<last;k++)
    {
        // ofp_flow_stats fixed fields are the same length with ofp_flow_mod
        flow_stats.length = flow_table->flow_match13[k].header.length;
        flow_stats.table_id = flow_table->flow_match13[k].table_id;
        flow_stats.duration_sec = htonl(current_time - flow_table->flow_counters[k].duration);
        flow_stats.duration_nsec = htonl(0);
        flow_stats.priority = flow_table->flow_match13[k].priority;
        flow_stats.idle_timeout = flow_table->flow_match13[k].idle_timeout;
        flow_stats.hard_timeout = flow_table->flow_match13[k].hard_timeout;
        flow_stats.flags = flow_table->flow_match13[k].flags;
        flow_stats.cookie = flow_table->flow_match13[k].cookie;
        flow_stats.packet_count = _htonll(flow_table->flow_counters[k].hitCount);
        flow_stats.byte_count = _htonll(flow_table->flow_counters[k].bytes);
        flow_stats.match = flow_table->flow_match13[k].match;
        
        if(buffer_ptr + ntohs(flow_stats.length) > buffer + 16384)
        {
            break; // XXX: should provide multipart OFPMPF_REPLY_MORE flow
        }
        // struct ofp13_flow_stats(including ofp13_match)
        memcpy(buffer_ptr, &flow_stats, sizeof(struct ofp13_flow_stats));
        // oxm_fields
        len = offsetof(struct ofp13_flow_stats, match) + offsetof(struct ofp13_match, oxm_fields);
        memcpy(buffer_ptr + len, flow_table->ofp13_oxm[k].match, ntohs(flow_stats.match.length) - 4);
        // instructions
        len = offsetof(struct ofp13_flow_stats, match) + ALIGN8(ntohs(flow_stats.match.length));
        memcpy(buffer_ptr + len, flow_table->ofp13_oxm[k].inst, ntohs(flow_stats.length) - len);
        buffer_ptr += ntohs(flow_stats.length);
    }
    return (buffer_ptr - buffer);
}


