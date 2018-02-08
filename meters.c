//
//  meters.c
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

#include <sys/types.h>

#include "openflow.h"
#include "meters.h"

extern struct flow_table *flow_table;
extern int current_time;
extern int OF_Version;

static inline uint64_t (_htonll)(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

/*
 *	Main OpenFlow Meter Statistics message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_meter_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
    struct ofp13_meter_stats meter_stats;
    struct ofp13_multipart_reply reply;
    struct ofp13_meter_multipart_request *meter_stats_req = req->body;
    uint32_t req_id = ntohl(meter_stats_req->meter_id);
    uint8_t *buffer_ptr = buffer;
    
    if(req_id == OFPM13_ALL)
    {
        /* Reply with all meter stats*/
        
        // Count the number of meters configured, and the total number of bands
        int meter_index = 0;
        uint16_t bands_counter = 0;
        while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
        {
            bands_counter += flow_table->meter_table.meter_entry[meter_index].band_count;
            meter_index++;
        };
        
        // Calculate total size - replysize + (number of meters)*statssize + (total number of bands)*bandsize
        uint16_t	total_size = sizeof(struct ofp13_multipart_reply) + (meter_index*sizeof(struct ofp13_meter_stats)) + (bands_counter*sizeof(struct ofp13_meter_band_stats));
        
        // Format reply
        reply.type				= htons(OFPMP13_METER);
        reply.flags				= 0;	// Single reply
        
        // Format header
        reply.header.version	= OF_Version;
        reply.header.type		= OFPT13_MULTIPART_REPLY;
        reply.header.length		= htons(total_size);
        reply.header.xid		= req->header.xid;
        
        // Copy reply
        memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
        buffer_ptr += sizeof(struct ofp13_multipart_reply);
        
        meter_index = 0;
        // Loop & format each meter stats reply
        while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
        {
            // Format reply with specified meter statistics
            meter_stats.meter_id		= htonl(flow_table->meter_table.meter_entry[meter_index].meter_id);
            meter_stats.len				= htons(sizeof(struct ofp13_meter_stats) + (flow_table->meter_table.meter_entry[meter_index].band_count*sizeof(struct ofp13_meter_band_stats)));
            
            flow_table->meter_table.meter_entry[meter_index].flow_count = get_bound_flows(req_id);
            meter_stats.flow_count		= htonl(flow_table->meter_table.meter_entry[meter_index].flow_count);
            
            meter_stats.packet_in_count = _htonll(flow_table->meter_table.meter_entry[meter_index].packet_in_count);
            meter_stats.byte_in_count	= _htonll(flow_table->meter_table.meter_entry[meter_index].byte_in_count);
            meter_stats.duration_sec	= htonl((current_time-flow_table->meter_table.meter_entry[meter_index].time_added));
            meter_stats.duration_nsec	= 0;	// nanosecond accuracy unsupported
            
            // Copy configuration
            memcpy(buffer_ptr, &meter_stats, sizeof(struct ofp13_meter_stats));
            buffer_ptr += sizeof(struct ofp13_meter_stats);
            
            // Format bands
            int bands_processed = 0;
            struct ofp13_meter_band_stats * ptr_buffer_band;
            ptr_buffer_band = buffer_ptr;
            
            while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
            {
                ptr_buffer_band->packet_band_count	= _htonll(flow_table->meter_table.band_stats_array[meter_index].band_stats[bands_processed].byte_band_count);
                ptr_buffer_band->byte_band_count	= _htonll(flow_table->meter_table.band_stats_array[meter_index].band_stats[bands_processed].packet_band_count);
                
                ptr_buffer_band++;
                bands_processed++;
            }
            
            // update buffer pointer
            buffer_ptr = ptr_buffer_band;
            
            meter_index++;
        }
        
        return (buffer_ptr - buffer);	// return length
    }
    
    // Find meter entry with specified meter id
    int meter_index = 0;
    while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
    {
        if(flow_table->meter_table.meter_entry[meter_index].meter_id == req_id)
        {
            break;
        }
        
        meter_index++;
    }
    if(flow_table->meter_table.meter_entry[meter_index].active==0 || meter_index == MAX_METER_13)
    {
        of_error13(req, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);
        
        return 0;	// return length
    }
    
    // Calculate total size
    uint16_t total_size = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_meter_stats) + (flow_table->meter_table.meter_entry[meter_index].band_count*sizeof(struct ofp13_meter_band_stats));
    
    // Format reply
    reply.type				= htons(OFPMP13_METER);
    reply.flags				= 0;	// Single reply
    
    // Format header
    reply.header.version	= OF_Version;
    reply.header.type		= OFPT13_MULTIPART_REPLY;
    reply.header.length		= htons(total_size);
    reply.header.xid		= req->header.xid;
    
    // Copy reply
    memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
    buffer_ptr += sizeof(struct ofp13_multipart_reply);
    
    // Format reply with specified meter statistics
    meter_stats.meter_id		= htonl(req_id);
    meter_stats.len				= htons(total_size - sizeof(struct ofp13_multipart_reply));
    
    flow_table->meter_table.meter_entry[meter_index].flow_count = get_bound_flows(req_id);
    meter_stats.flow_count		= htonl(flow_table->meter_table.meter_entry[meter_index].flow_count);
    
    meter_stats.packet_in_count = _htonll(flow_table->meter_table.meter_entry[meter_index].packet_in_count);
    meter_stats.byte_in_count	= _htonll(flow_table->meter_table.meter_entry[meter_index].byte_in_count);
    meter_stats.duration_sec	= htonl((current_time-flow_table->meter_table.meter_entry[meter_index].time_added));
    meter_stats.duration_nsec	= 0;	// nanosecond accuracy unsupported
    
    
    // Copy configuration
    memcpy(buffer_ptr, &meter_stats, sizeof(struct ofp13_meter_stats));
    buffer_ptr += sizeof(struct ofp13_meter_stats);
    
    // Format bands
    int bands_processed = 0;
    struct ofp13_meter_band_stats * ptr_buffer_band;
    ptr_buffer_band = buffer_ptr;
    
    while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
    {
        ptr_buffer_band->packet_band_count	= _htonll(flow_table->meter_table.band_stats_array[meter_index].band_stats[bands_processed].byte_band_count);
        ptr_buffer_band->byte_band_count	= _htonll(flow_table->meter_table.band_stats_array[meter_index].band_stats[bands_processed].packet_band_count);
        
        ptr_buffer_band++;
        bands_processed++;
    }
    
    // update buffer pointer
    buffer_ptr = ptr_buffer_band;
    
    return (buffer_ptr - buffer);	// return length
}

/*
 *	Main OpenFlow Meter Configuration message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_meter_config_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
    struct ofp13_meter_config meter_config;
    struct ofp13_multipart_reply reply;
    struct ofp13_meter_multipart_request *meter_config_req = req->body;
    uint32_t req_id = ntohl(meter_config_req->meter_id);
    uint8_t *buffer_ptr = buffer;
    
    if(req_id == OFPM13_ALL)
    {
        /* Reply with all meter configurations */
        
        // Count the number of meters configured, and the total number of bands
        int meter_index = 0;
        uint16_t bands_counter = 0;
        while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
        {
            bands_counter += flow_table->meter_table.meter_entry[meter_index].band_count;
            meter_index++;
        };
        
        // Calculate total size - replysize + (number of meters)*configsize + (total number of bands)*bandsize
        uint16_t	total_size = sizeof(struct ofp13_multipart_reply) + (meter_index*sizeof(struct ofp13_meter_config)) + (bands_counter*sizeof(struct ofp13_meter_band_drop));
        
        // Format reply
        reply.type				= htons(OFPMP13_METER_CONFIG);
        reply.flags				= 0;	// Single reply
        
        // Format header
        reply.header.version	= OF_Version;
        reply.header.type		= OFPT13_MULTIPART_REPLY;
        reply.header.length		= htons(total_size);
        reply.header.xid		= req->header.xid;
        
        // Copy reply
        memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
        buffer_ptr += sizeof(struct ofp13_multipart_reply);
        
        meter_index = 0;
        // Loop & format each meter config reply
        while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
        {
            // Format reply with specified meter configuration
            meter_config.length		= htons(sizeof(struct ofp13_meter_config) + (flow_table->meter_table.meter_entry[meter_index].band_count*sizeof(struct ofp13_meter_band_drop)));
            meter_config.flags		= htons(flow_table->meter_table.meter_entry[meter_index].flags);
            meter_config.meter_id	= htonl(flow_table->meter_table.meter_entry[meter_index].meter_id);
            
            // Copy configuration
            memcpy(buffer_ptr, &meter_config, sizeof(struct ofp13_meter_config));
            buffer_ptr += sizeof(struct ofp13_meter_config);
            
            // Format bands
            int bands_processed = 0;
            struct ofp13_meter_band_drop * ptr_band;
            ptr_band = &(flow_table->meter_table.meter_entry[meter_index].bands[0]);
            struct ofp13_meter_band_drop * ptr_buffer_band;
            ptr_buffer_band = (struct ofp13_meter_band_drop*) buffer_ptr;
            
            while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
            {
                ptr_buffer_band->type		= htons(ptr_band->type);
                ptr_buffer_band->len		= htons(sizeof(struct ofp13_meter_band_drop));
                ptr_buffer_band->rate		= htonl(ptr_band->rate);
                ptr_buffer_band->burst_size	= htonl(ptr_band->burst_size);
                
                ptr_buffer_band++;
                ptr_band++;	// Move to next band
                bands_processed++;
            }
            
            // update buffer pointer
            buffer_ptr = (uint8_t*) ptr_buffer_band;
            
            meter_index++;
        }
        
        return (int)(buffer_ptr - buffer);	// return length
    }

    // Find meter entry with specified meter id
    int meter_index = 0;
    while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
    {
        if(flow_table->meter_table.meter_entry[meter_index].meter_id == req_id)
        {
            break;
        }
        
        meter_index++;
    }
    if(flow_table->meter_table.meter_entry[meter_index].active==0 || meter_index == MAX_METER_13)
    {
        of_error13(req, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);
        return 0;	// return length
    }
    
    // Calculate total size
    uint16_t total_size = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_meter_config) + (flow_table->meter_table.meter_entry[meter_index].band_count*sizeof(struct ofp13_meter_band_drop));
    
    // Format reply
    reply.type				= htons(OFPMP13_METER_CONFIG);
    reply.flags				= 0;	// Single reply
    
    // Format header
    reply.header.version	= OF_Version;
    reply.header.type		= OFPT13_MULTIPART_REPLY;
    reply.header.length		= htons(total_size);
    reply.header.xid		= req->header.xid;
    
    // Copy reply
    memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
    buffer_ptr += sizeof(struct ofp13_multipart_reply);
    
    // Format reply with specified meter configuration
    meter_config.length		= htons(total_size - sizeof(struct ofp13_multipart_reply));
    meter_config.flags		= htons(flow_table->meter_table.meter_entry[meter_index].flags);
    meter_config.meter_id	= htonl(req_id);
    
    // Copy configuration
    memcpy(buffer_ptr, &meter_config, sizeof(struct ofp13_meter_config));
    buffer_ptr += sizeof(struct ofp13_meter_config);
    
    // Format bands
    int bands_processed = 0;
    struct ofp13_meter_band_drop * ptr_band;
    ptr_band = &(flow_table->meter_table.meter_entry[meter_index].bands[0]);
    struct ofp13_meter_band_drop * ptr_buffer_band;
    ptr_buffer_band = (struct ofp13_meter_band_drop*)buffer_ptr;
    
    while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
    {
        ptr_buffer_band->type		= htons(ptr_band->type);
        ptr_buffer_band->len		= htons(sizeof(struct ofp13_meter_band_drop));
        ptr_buffer_band->rate		= htonl(ptr_band->rate);
        ptr_buffer_band->burst_size	= htonl(ptr_band->burst_size);
        
        ptr_buffer_band++;
        ptr_band++;	// Move to next band
        bands_processed++;
    }
    
    // update buffer pointer
    buffer_ptr = (uint8_t*)ptr_buffer_band;
    
    return (int)(buffer_ptr - buffer);	// return length
}

/*
 *	Main OpenFlow Meter Features message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_meter_features_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
    struct ofp13_meter_features meter_features;
    struct ofp13_multipart_reply reply;
    uint8_t *buffer_ptr = buffer;
    
    // Format reply
    reply.type				= htons(OFPMP13_METER_FEATURES);
    reply.flags				= 0;	// Single reply
    
    // Format header
    reply.header.version	= OF_Version;
    reply.header.type		= OFPT13_MULTIPART_REPLY;
    reply.header.length		= htons(sizeof(struct ofp13_meter_features) + sizeof(struct ofp13_multipart_reply));
    reply.header.xid		= req->header.xid;
    
    // Copy reply
    memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
    buffer_ptr += sizeof(struct ofp13_multipart_reply);
    
    // Format reply with meter features
    meter_features.max_meter	= htonl(MAX_METER_13);
    meter_features.band_types	= htonl(1<<OFPMBT13_DSCP_REMARK | 1<<OFPMBT13_DROP);		// Only OFPMBT_DROP supported
    meter_features.capabilities	= htonl(OFPMF13_KBPS | OFPMF13_PKTPS);
    meter_features.max_bands	= MAX_METER_BANDS_13;
    meter_features.max_color	= 0;
    
    // Copy configuration
    
    memcpy(buffer_ptr, &meter_features, sizeof(struct ofp13_meter_features));
    buffer_ptr += sizeof(struct ofp13_meter_features);
    
    return (buffer_ptr - buffer);	// return length
}

/*
 *	Main OpenFlow METER_MOD message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void meter_mod13(struct ofp_header *msg)
{
    struct ofp13_meter_mod * ptr_mm;
    ptr_mm = (struct ofp13_meter_mod *) msg;
    
    switch(ntohs(ptr_mm->command))
    {
        case OFPMC13_ADD:
            meter_add13(msg);
            break;
            
        case OFPMC13_MODIFY:
            meter_modify13(msg);
            break;
            
        case OFPMC13_DELETE:
            meter_delete13(msg);
            break;
    }
    
    return;
}

/*
 *	OpenFlow METER_ADD function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void meter_add13(struct ofp_header *msg)
{
    // Check if final table entry is populated
    if(flow_table->meter_table.meter_entry[(MAX_METER_13)-1].active==1)
    {
        of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_METERS);
        return;
    }
    
    struct ofp13_meter_mod * ptr_mm;
    ptr_mm = (struct ofp13_meter_mod *) msg;
    
    // Check for existing meter
    int meter_index = 0;
    while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
    {
        if(ntohl(ptr_mm->meter_id) == flow_table->meter_table.meter_entry[meter_index].meter_id)
        {
            of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_METER_EXISTS);
            return;
        }
        
        meter_index++;
    }
    // meter_index now holds the next available entry in the meter table
    
    // Find number of bands
    uint16_t bands_received = ((ntohs(ptr_mm->header.length) - sizeof(struct ofp_header) - METER_PARTIAL))/sizeof(struct ofp13_meter_band_drop);	// FIX
    // Band list length is inferred from the length field in the header
    
    if(bands_received > MAX_METER_BANDS_13)
    {
        of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
        return;
    }
    
    // Set entry as active
    flow_table->meter_table.meter_entry[meter_index].active = 1;
    
    // Copy meter configs over
    flow_table->meter_table.meter_entry[meter_index].meter_id = ntohl(ptr_mm->meter_id);
    flow_table->meter_table.meter_entry[meter_index].flags = ntohs(ptr_mm->flags);
    flow_table->meter_table.meter_entry[meter_index].band_count = bands_received;
    
    // Initialise time added
    flow_table->meter_table.meter_entry[meter_index].time_added = current_time;
    
    // Copy bands over
    if(bands_received != 0)
    {
        struct ofp13_meter_band_drop * ptr_band;
        uint16_t bands_processed = 0;
        
        // Initialise pointer to first meter band destination
        ptr_band = &(flow_table->meter_table.meter_entry[meter_index].bands[0]);
        struct ofp13_meter_band_drop * ptr_rxband;
        ptr_rxband = (struct ofp13_meter_band_drop*)&(ptr_mm->bands[0]);
        
        do
        {
            // Copy individual band
            //memcpy((ptr_band + band_size*bands_processed), ((ptr_mm->bands) + band_size*bands_processed), PADDED_BAND_LEN);
            //ptr_band->type			= ntohs(ptr_mm->bands[bands_processed].type);
            //ptr_band->len			= ntohs(ptr_mm->bands[bands_processed].len);
            //ptr_band->rate			= ntohl(ptr_mm->bands[bands_processed].rate);
            //ptr_band->burst_size	= ntohl(ptr_mm->bands[bands_processed].burst_size);
            
            ptr_band->type			= ntohs(ptr_rxband->type);
            ptr_band->len			= ntohs(ptr_rxband->len);
            ptr_band->rate			= ntohl(ptr_rxband->rate);
            ptr_band->burst_size	= ntohl(ptr_rxband->burst_size);
            
            // Copy DSCP precedence level
            if(ptr_band->type == OFPMBT13_DSCP_REMARK)
            {
                ((struct ofp13_meter_band_dscp_remark*)ptr_band)->prec_level = ((struct ofp13_meter_band_dscp_remark*)ptr_rxband)->prec_level;
            }
            
            ptr_band++;		// Move to next band storage location
            ptr_rxband++;	// Move to next received band
            bands_processed++;
            
            // ***** TODO : add error checking for band processing
            
        } while (bands_processed < bands_received);
    }
    
    flow_table->meter_table.iLastMeter++;	// Decrement last meter count
    
    return;
}

/*
 *	OpenFlow METER_MODIFY function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void meter_modify13(struct ofp_header *msg)
{
    struct ofp13_meter_mod * ptr_mm;
    ptr_mm = (struct ofp13_meter_mod *) msg;
    uint32_t req_id = ntohl(ptr_mm->meter_id);

    // Find meter entry with specified meter id
    int meter_index = 0;
    while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
    {
        if(flow_table->meter_table.meter_entry[meter_index].meter_id == req_id)
        {
            break;
        }
        
        meter_index++;
    }
    if(flow_table->meter_table.meter_entry[meter_index].active==0 || meter_index == MAX_METER_13)
    {
        of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);
        
        return;	// return length
    }
    
    // Find number of bands in received entry
    uint16_t bands_received = ((ntohs(ptr_mm->header.length) - sizeof(struct ofp_header) - METER_PARTIAL))/sizeof(struct ofp13_meter_band_drop);    //FIX
    // Band list length is inferred from the length field in the header
    if(bands_received > MAX_METER_BANDS_13)
    {
        of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
        return;
    }
    
    // Store the top-level meter statistics
    struct meter_entry13 entry_save = {0};
    entry_save = flow_table->meter_table.meter_entry[meter_index];
    
    // Set entry inactive
    flow_table->meter_table.meter_entry[meter_index].active = 0;
    
    /* Delete band counters */
    // Create temporary empty structure
    struct meter_band_stats_array empty_stats_array = {0};
    // Copy over the existing structure
    flow_table->meter_table.band_stats_array[meter_index] = empty_stats_array;
    
    // Set meter entry active
    flow_table->meter_table.meter_entry[meter_index].active = 1;
    
    // Restore top-level statistics
    flow_table->meter_table.meter_entry[meter_index] = entry_save;
    
    // Update modified configs
    flow_table->meter_table.meter_entry[meter_index].flags = ntohs(ptr_mm->flags);
    flow_table->meter_table.meter_entry[meter_index].band_count = bands_received;
    
    // Copy bands over
    if(bands_received != 0)
    {
        struct ofp13_meter_band_drop * ptr_band;
        uint16_t bands_processed = 0;
        
        // Initialise pointer to first meter band destination
        ptr_band = &(flow_table->meter_table.meter_entry[meter_index].bands[0]);
        struct ofp13_meter_band_drop * ptr_rxband;
        ptr_rxband = (struct ofp13_meter_band_drop*) &(ptr_mm->bands[0]);
        
        do
        {
            // Copy individual band
            //memcpy((ptr_band + band_size*bands_processed), ((ptr_mm->bands) + band_size*bands_processed), PADDED_BAND_LEN);
            //ptr_band->type			= ntohs(ptr_mm->bands[bands_processed].type);
            //ptr_band->len			= ntohs(ptr_mm->bands[bands_processed].len);
            //ptr_band->rate			= ntohl(ptr_mm->bands[bands_processed].rate);
            //ptr_band->burst_size	= ntohl(ptr_mm->bands[bands_processed].burst_size);
            
            ptr_band->type			= ntohs(ptr_rxband->type);
            ptr_band->len			= ntohs(ptr_rxband->len);
            ptr_band->rate			= ntohl(ptr_rxband->rate);
            ptr_band->burst_size	= ntohl(ptr_rxband->burst_size);
            
            // Copy DSCP precedence level
            if(ptr_band->type == OFPMBT13_DSCP_REMARK)
            {
                ((struct ofp13_meter_band_dscp_remark*)ptr_band)->prec_level = ((struct ofp13_meter_band_dscp_remark*)ptr_rxband)->prec_level;
            }
            
            // ***** TODO : add error checking for band processing
            ptr_band++;		// Move to next band storage location
            ptr_rxband++;	// Move to next received band
            bands_processed++;
        } while (bands_processed < bands_received);
    }
    
    return;
}

/*
 *	OpenFlow METER_DELETE function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void meter_delete13(struct ofp_header *msg)
{
    struct ofp13_meter_mod * ptr_mm;
    ptr_mm = (struct ofp13_meter_mod *) msg;
    
    // Check if all meters need to be deleted
    if(ntohl(ptr_mm->meter_id) == OFPM13_ALL)
    {
        int meter_index = 0;
        
        // Create temporary empty structure
        struct meter_band_stats_array empty_stats_array = {0};
        
        // Loop through all meters
        while(flow_table->meter_table.meter_entry[meter_index].active==1 && meter_index < MAX_METER_13)
        {
            /* Delete entry */
            // Set entry inactive
            flow_table->meter_table.meter_entry[meter_index].active = 0;
            
            /* Delete band counters */
            // Copy over the existing structure
            flow_table->meter_table.band_stats_array[meter_index] = empty_stats_array;
            
            meter_index++;
        }
        
        return;
    }

    int meter_index = 0;
    int meter_location = -1;
    // Loop through existing meters
    while(flow_table->meter_table.meter_entry[meter_index].active == 1 && meter_index < MAX_METER_13 && meter_location == -1)
    {
        // Compare requested meter_id with entry's meter_id
        if(ntohl(ptr_mm->meter_id) == flow_table->meter_table.meter_entry[meter_index].meter_id)
        {
            // Store the index
            meter_location = meter_index;
        }
        
        meter_index++;
    }
    
    if(meter_location == -1)
    {
        // No error message required
        return;
    }
    
    /* Delete entry */
    flow_table->meter_table.meter_entry[meter_location].active = 0;
    meter_index = meter_location;
    
    /* Delete band counters */
    // Create temporary empty structure
    struct meter_band_stats_array empty_stats_array = {0};
    // Copy over the existing structure
    flow_table->meter_table.band_stats_array[meter_index] = empty_stats_array;
    
    // Consolidate table
    if(flow_table->meter_table.meter_entry[meter_index+1].active != 0)
    {
        // Increment the index until the last meter entry is found
        while(flow_table->meter_table.meter_entry[meter_index+1].active==1 && (meter_index+1) < MAX_METER_13)
        {
            meter_index++;
        }
        flow_table->meter_table.meter_entry[meter_location] = flow_table->meter_table.meter_entry[meter_index];	// Move last entry into deleted entry location
        flow_table->meter_table.meter_entry[meter_index].active = 0;	// Zero the moved entry
        
        /* Consolidate meter bands */
        // Copy last meter's band counters into the deleted entry's band counters
        flow_table->meter_table.band_stats_array[meter_location] = flow_table->meter_table.band_stats_array[meter_index];
        // Zero the moved band counters
        flow_table->meter_table.band_stats_array[meter_index] = empty_stats_array;
    }
    
    flow_table->meter_table.iLastMeter--;	// Decrement last meter count
    
    return;
}

/*
 *	Retrieve number of flows bound to the specified meter
 *
 *	@param	id		- meter ID to check
 *
 *	@ret	count	- number of associated flows
 *
 */
uint32_t get_bound_flows(uint32_t id)
{
    uint32_t count = 0;
    
    // Loop through flows
    for (int i=0;i<flow_table->iLastFlow;i++)
    {
        struct ofp13_instruction *inst_ptr;
        void *insts[8] = {0};
        int inst_size = 0;
        while(inst_size < flow_table->ofp13_oxm[i].inst_size){
            inst_ptr = (uint8_t*)&flow_table->ofp13_oxm[i].inst + inst_size;
            insts[ntohs(inst_ptr->type)] = inst_ptr;
            inst_size += ntohs(inst_ptr->len);
        }
        
        // Check if metering instruction is present
        if(insts[OFPIT13_METER] != NULL)
        {
            struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
            // Check the found meter id
            if(ntohl(inst_meter->meter_id) == id)
            {
                // The flow's instruction matches the specified meter id
                count++;	// increment the counter
            }
        }
    }
    
    return count;
}
