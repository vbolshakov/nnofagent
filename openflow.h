/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <stdbool.h>
#include <poll.h>
#include <netinet/in.h>
#include "openflow_spec.h"
#include "openflow13.h"

#define MAX_FLOWS_13    512
#define MAX_TABLES      16
#define SHARED_BUFFER_LEN 65536
#define PACKET_BUFFER 32
#define PACKET_BUFFER_SIZE 256

#define MAX_METER_13        8	// Maximum number of meter entries in meter table
#define MAX_METER_BANDS_13  3	// Maximum number of meter bands per meter
#define POLICING_SAMPLES    20	// Sample for rate limiter
#define POLICING_SLICE      2	// time (ms) slice for each sample
#define	METER_PARTIAL	8		// Meter structure length, excluding header and bands
/* Meter processing defines */
#define METER_DROP	-1	// drop packet
#define METER_NOACT	0	// no action
#define MAX_GROUPS 8
#define MAX_BUCKETS 8

#define ETH_PORT_NO 65

#define PB_EMPTY 0
#define PB_PACKETIN 1
#define PB_PACKETOUT 2
#define PB_PENDING 3

struct flows_counter
{
    uint64_t hitCount;
    uint64_t bytes;
    uint32_t duration;
    uint8_t active;
    int lastmatch;
};

struct table_counter
{
    uint64_t lookup_count;
    uint64_t matched_count;
    uint64_t byte_count;
};

struct oxm_header13
{
    uint16_t oxm_class;
    uint8_t oxm_field;
    uint8_t oxm_len;
};

struct ofp13_oxm
{
    uint8_t match[128];
    uint8_t inst[1100];
    uint16_t match_size;
    uint16_t inst_size;
};

struct group_table {
    int active;
    uint8_t type;
    uint8_t pad;
    uint32_t group_id;
    uint8_t bucket_id;
    uint64_t packet_count;
    uint64_t byte_count;
    int time_added;
};

struct action_bucket {
    int active;
    uint64_t packet_count;
    uint64_t byte_count;
    uint8_t data[1100];
};

/*
 *	OpenFlow meter entry structure
 *		Meter table is populated with these entries.
 *		The structure contains:
 *			- meter ID
 *			- counters
 *			- meter bands
 */
struct meter_entry13
{
    uint32_t	meter_id;
    uint32_t	flow_count;			// Number of flows bound to meter
    uint64_t	packet_in_count;	// Packets processed by meter
    uint64_t	byte_in_count;		// Bytes processed by meter
    uint32_t	time_added;			// Time meter was added in ms (time alive calculated when required)
    uint16_t	flags;				// Meter configuration flags
    uint16_t	band_count;			// Number of bands in this meter
    time_t	last_packet_in;		// Time when meter last processed a packet (milliseconds)
    uint8_t active;             // Set if entry is valid
    struct ofp13_meter_band_drop bands[MAX_METER_BANDS_13];	// Meter bands
};

/*
 *	Meter band counters
 *		Each instance of meter_band_stats_array contains
 *		statistics for the maximum number of supported
 *		bands.
 *
 */
struct meter_band_stats_array
{
    struct ofp13_meter_band_stats band_stats[MAX_METER_BANDS_13];
};

struct policing_sample
{
	uint32_t	packet_time;	// (time) when sampled
	uint16_t	byte_count;		// Number of bytes during this sample
	uint16_t	packet_count;	// Number of packets during this sample
};

struct meter_sample_array
{
	uint16_t	sample_index;
	struct		policing_sample sample[POLICING_SAMPLES];
};

struct meter_table
{
    int iLastMeter;
    struct meter_entry13           meter_entry[MAX_METER_13];
    struct meter_band_stats_array   band_stats_array[MAX_METER_13];
};

struct flow_table
{
    int iLastFlow;
    int enabled;
    int auth_bypass;
    int port_status[ETH_PORT_NO];
    struct ofp13_flow_mod   flow_match13[MAX_FLOWS_13];
    struct ofp13_oxm        ofp13_oxm[MAX_FLOWS_13];
    struct flows_counter    flow_counters[MAX_FLOWS_13];
    struct ofp13_port_stats phys13_port_stats[ETH_PORT_NO];
    struct table_counter    table_counters[MAX_TABLES];
    struct group_table      group_table[MAX_GROUPS];
    struct action_bucket    action_buckets[MAX_BUCKETS];
    struct meter_table      meter_table;
};

struct packet_buffer
{
    uint8_t type;
    uint8_t age;
    uint16_t size;
    uint32_t inport;
    uint8_t reason;
    uint8_t flow;
    uint8_t table_id;
    uint32_t outport;
    struct net_device *dev;
    struct sk_buff *skb;
    uint8_t buffer[PACKET_BUFFER_SIZE];
};

struct pbuffer
{
    struct packet_buffer buffer[PACKET_BUFFER];
};

void OF_hello(void);

void openflowswitch_handle_read();
void openflowswitch_set_pollfd(struct pollfd *pfd);
void openflowswitch_handle_io(const struct pollfd *pfd);
void of_timer(void);
void flow_timeouts(void);


