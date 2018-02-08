//
//  groups.c
//  nnofagent
//
//  Created by Paul Zanna on 26/8/17.
//  Copyright © 2017 Northbound Networks. All rights reserved.
//

#include <sys/types.h>

#include "openflow.h"
#include "groups.h"

extern struct flow_table *flow_table;
extern int OF_Version;
extern int current_time;

static inline uint64_t (_htonll)(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

/*
 *	OpenFlow Multi-part GROUP Features reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_features_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_multipart_reply reply;
    struct ofp13_group_features group_features;
    uint8_t *buffer_ptr = buffer;
    
    // Format reply
    reply.type				= htons(OFPMP13_GROUP_FEATURES);
    reply.flags				= 0;	// Single reply
    
    // Format header
    reply.header.version	= OF_Version;
    reply.header.type		= OFPT13_MULTIPART_REPLY;
    reply.header.length		= htons(sizeof(struct ofp13_group_features) + sizeof(struct ofp13_multipart_reply));
    reply.header.xid		= msg->header.xid;
    
    group_features.types = htonl(1);     // Only support OFPGT_ALL for the moment
    group_features.capabilities = 0;
    group_features.max_groups[0] = htonl(8); // Suport 8 OFPGT_ALL groups
    group_features.max_groups[1] = 0;
    group_features.max_groups[1] = 0;
    group_features.max_groups[1] = 0;
    group_features.actions[0] = htonl((1 << OFPAT13_OUTPUT) + (1 << OFPAT13_PUSH_VLAN)+ (1 << OFPAT13_POP_VLAN));
    group_features.actions[1] = 0;
    group_features.actions[2] = 0;
    group_features.actions[3] = 0;
    
    memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
    buffer_ptr += sizeof(struct ofp13_multipart_reply);
    memcpy(buffer_ptr, &group_features, sizeof(struct ofp13_group_features));

    buffer_ptr += sizeof(struct ofp13_group_features);
    return (buffer_ptr - buffer);	// return length
}


/*
 *	OpenFlow Multi-part GROUP Description reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_multipart_reply *reply;
    reply = (struct ofp13_multipart_reply *)buffer;
    struct ofp13_group_desc group_desc;
    uint8_t *buffer_ptr = buffer + sizeof(struct ofp13_multipart_reply);
    int i;
    uint16_t len = 0;

    // Build group desc and add the reply
    for(i=0;i<MAX_GROUPS;i++)
    {
        if (flow_table->group_table[i].active == true)
        {
            group_desc.group_id = htonl(flow_table->group_table[i].group_id);
            group_desc.type= flow_table->group_table[i].type;
            if (flow_table->group_table[i].bucket_id > 0)
            {
                struct ofp13_bucket *ptr_bucket;
                ptr_bucket = (struct ofp13_bucket*)flow_table->action_buckets[flow_table->group_table[i].bucket_id-1].data;
                group_desc.length = htons(sizeof(struct ofp13_group_desc) + ntohs(ptr_bucket->len));
                memcpy(buffer_ptr, &group_desc, sizeof(struct ofp13_group_desc));
                buffer_ptr += sizeof(struct ofp13_group_desc);
                memcpy(buffer_ptr, ptr_bucket, ntohs(ptr_bucket->len));
                len += sizeof(struct ofp13_group_desc) + ntohs(ptr_bucket->len);
                buffer_ptr += ntohs(ptr_bucket->len);
            } else {
                memcpy(buffer_ptr, &group_desc, sizeof(struct ofp13_group_desc));
                len += sizeof(struct ofp13_group_desc);
                buffer_ptr += sizeof(struct ofp13_group_desc);
            }
        }
    }
    len += sizeof(struct ofp13_multipart_reply);
    // Format header
    reply->header.version	= OF_Version;
    reply->header.type		= OFPT13_MULTIPART_REPLY;
    reply->header.xid		= msg->header.xid;
    reply->header.length = htons(len);
    // Format reply
    reply->type				= htons(OFPMP13_GROUP_DESC);
    reply->flags			= 0;	// Single reply
    memcpy(buffer, reply, sizeof(struct ofp13_multipart_reply));
    return len;
}

/*
 *	OpenFlow Multi-part GROUP Statistics reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_group_stats group_stats;
    struct ofp13_multipart_reply *reply;
    struct ofp13_bucket_counter bucket_counters;
    reply = (struct ofp13_multipart_reply *)buffer;
    uint8_t *buffer_ptr = buffer + sizeof(struct ofp13_multipart_reply);
    int i;
    uint16_t len = 0;

    
    // Build group desc and add the reply
    for(i=0;i<MAX_GROUPS;i++)
    {
        if (flow_table->group_table[i].active == true)
        {
            group_stats.group_id = htonl(flow_table->group_table[i].group_id);
            if (flow_table->group_table[i].bucket_id > 0)
            {
                group_stats.byte_count = _htonll(flow_table->group_table[i].byte_count);
                group_stats.packet_count = _htonll(flow_table->group_table[i].packet_count);
                group_stats.duration_sec = htonl((current_time-flow_table->group_table[i].time_added));
                group_stats.ref_count = 0;
                group_stats.length = htons(sizeof(struct ofp13_group_stats) + sizeof(struct ofp13_bucket_counter));
                memcpy(buffer_ptr, &group_stats, sizeof(struct ofp13_group_stats));
                buffer_ptr += sizeof(struct ofp13_group_stats);
                bucket_counters.byte_count = _htonll(flow_table->action_buckets[flow_table->group_table[i].bucket_id-1].byte_count);
                bucket_counters.packet_count = _htonll(flow_table->action_buckets[flow_table->group_table[i].bucket_id-1].packet_count);
                memcpy(buffer_ptr, &bucket_counters, sizeof(struct ofp13_bucket_counter));
                len += sizeof(struct ofp13_group_stats) + sizeof(struct ofp13_bucket_counter);
                buffer_ptr += sizeof(struct ofp13_bucket_counter);
            } else {
                memcpy(buffer_ptr, &group_stats, sizeof(struct ofp13_group_stats));
                len += sizeof(struct ofp13_group_stats);
                buffer_ptr += sizeof(struct ofp13_group_stats);
            }
        }
    }
    len += sizeof(struct ofp13_multipart_reply);
    // Format header
    reply->header.version	= OF_Version;
    reply->header.type		= OFPT13_MULTIPART_REPLY;
    reply->header.xid		= msg->header.xid;
    reply->header.length = htons(len);
    // Format reply
    reply->type				= htons(OFPMP13_GROUP);
    reply->flags			= 0;	// Single reply
    memcpy(buffer, reply, sizeof(struct ofp13_multipart_reply));
    return len;
}

/*
 *	Main OpenFlow GROUP_MOD message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_mod13(struct ofp_header *msg)
{
    struct ofp13_group_mod *ptr_fm;
    ptr_fm = (struct ofp13_group_mod *) msg;
    
    switch(htons(ptr_fm->command))
    {
        case OFPGC13_ADD:
            group_add13(msg);
            break;
            
        case OFPGC13_DELETE:
            group_delete13(msg);
            break;
            
        case OFPGC13_MODIFY:
            group_modify13(msg);
            break;
    }
    return;
}

/*
 *	OpenFlow GROUP_ADD function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_add13(struct ofp_header *msg)
{
    int g, b;
    int bucket_len;
    uint8_t *ptr_bucket;
    struct ofp13_group_mod *ptr_gm;
    ptr_gm = (struct ofp13_group_mod *)msg;
    
    //check for existing group ID
    for(g=0;g<MAX_GROUPS;g++)
    {
        if (flow_table->group_table[g].active == true && flow_table->group_table[g].group_id == ntohl(ptr_gm->group_id))
        {
            of_error13(msg, OFPET13_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS);
            return;
        }
    }
    
    // Find first empty group entry
    for(g=0;g<MAX_GROUPS;g++)
    {
        if (flow_table->group_table[g].active == false)
        {
            flow_table->group_table[g].active = true;
            flow_table->group_table[g].group_id = ntohl(ptr_gm->group_id);
            flow_table->group_table[g].type = ptr_gm->type;
            flow_table->group_table[g].time_added = current_time;
            // Find empty bucket
            for(b=0;b<MAX_BUCKETS;b++)
            {
                if (flow_table->action_buckets[b].active == false)
                {
                    printf("openflow_13.c: New bucket added to group %d - position %d\n", g, b);
                    bucket_len = ntohs(ptr_gm->header.length) - sizeof(struct ofp13_group_mod);
                    ptr_bucket = (uint8_t*)ptr_gm + sizeof(struct ofp13_group_mod);
                    if (bucket_len > 1099)
                    {
                        of_error13(msg, OFPET13_GROUP_MOD_FAILED, OFPGMFC_BAD_BUCKET);
                        return;
                    }
                    memcpy(flow_table->action_buckets[b].data, ptr_bucket, bucket_len);
                    flow_table->group_table[g].bucket_id = b + 1;
                    flow_table->action_buckets[b].active = true;
                    break;
                }
            }
            break;
        }
    }
    // TODO: add no groups and buckets available error
    return;
}

/*
 *	OpenFlow GROUP_DELETE function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_delete13(struct ofp_header *msg)
{
    int g;
    struct ofp13_group_mod *ptr_gm;
    ptr_gm = (struct ofp13_group_mod *)msg;
    
    for(g=0;g<MAX_GROUPS;g++)
    {
        if (htonl(ptr_gm->group_id) == flow_table->group_table[g].group_id || htonl(ptr_gm->group_id) == OFPG13_ALL)
        {
            flow_table->group_table[g].active = false;
            flow_table->action_buckets[flow_table->group_table[g].bucket_id-1].active = false;
            // TODO: remove associated flow entries too.
        }
    }
    return;
}

/*
 *	OpenFlow GROUP_MODIFY function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_modify13(struct ofp_header *msg)
{
    
    return;
}
