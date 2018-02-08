/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>

#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ifaddrs.h>

#include "openflow.h"
#include "agent.h"
#include "ofmsgbuf.h"

#define FTPAGES      256
#define PBPAGES      4 
#define PAGE_SIZE   4096

int current_time;
int sock;
struct ofmsgbuf *inbuf, *outbuf;    // input,output buffers
struct flow_table *flow_table;
struct pbuffer *pk_buffer;
char controller_ip_string[32];
int controller_port;
int enabled, auth_bypass, secure_disconnect;
uint8_t MAC_address[6];
int last_port_status[ETH_PORT_NO];

// Internal Functions
int timeout_connect(int fd, const char * hostname, int port, int mstimeout);
int make_tcp_connection_from_port(const char * hostname, unsigned short port, unsigned short sport, int mstimeout);
int make_tcp_connection(const char * hostname, unsigned short port, int mstimeout);
void openflowswitch_set_pollfd(struct pollfd *pfd);
void controller_connect(void);
void print_flows(void);
void print_meters(void);
void print_groups(void);
void clear_mmap(void);
void clear_flowtable(void);

static inline uint64_t (_htonll)(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

int timeout_connect(int fd, const char * hostname, int port, int mstimeout)
{
	int ret = 0;
	int flags;
	fd_set fds;
	struct timeval tv;
	struct addrinfo *res=NULL;
	struct addrinfo hints;
	char sport[BUFLEN];
	int err;
    
	hints.ai_flags          = 0;
	hints.ai_family         = AF_INET;
	hints.ai_socktype       = SOCK_STREAM;
	hints.ai_protocol       = IPPROTO_TCP;
	hints.ai_addrlen        = 0;
	hints.ai_addr           = NULL;
	hints.ai_canonname      = NULL;
	hints.ai_next           = NULL;
    
	snprintf(sport,BUFLEN,"%d",port);
    
	err = getaddrinfo(hostname,sport,&hints,&res);
	if(err|| (res==NULL))
	{
		if(res)
			freeaddrinfo(res);
		return -1;
	}

	// set non blocking
	if((flags = fcntl(fd, F_GETFL)) < 0) {
		freeaddrinfo(res);
		return -1;
	}
	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		freeaddrinfo(res);
		return -1;
	}
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
    
	if(mstimeout >= 0)
	{
		tv.tv_sec = mstimeout / 1000;
		tv.tv_usec = (mstimeout % 1000) * 1000;
        
		errno = 0;
        
		if(connect(fd, res->ai_addr, res->ai_addrlen) < 0)
		{
			if((errno != EWOULDBLOCK) && (errno != EINPROGRESS))
			{
				freeaddrinfo(res);
				return -1;
			}
		}
		ret = select(fd+1, NULL, &fds, NULL, &tv);
	}
	freeaddrinfo(res);
    
	if(ret != 1)
	{
		if(ret == 0)
			return -1;
		else
			return ret;
	}
	return 0;
}

int make_tcp_connection_from_port(const char * hostname, unsigned short port, unsigned short sport, int mstimeout)
{
    struct sockaddr_in local;
    int s;
    int err;
    
    s = socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        exit(1);  // bad socket
    }
    local.sin_family=PF_INET;
    local.sin_addr.s_addr=INADDR_ANY;
    local.sin_port=htons(sport);
    err=bind(s,(struct sockaddr *)&local, sizeof(local));
    if(err)
    {
        return -4;
    }
    err = timeout_connect(s,hostname,port, mstimeout);
    if(err)
    {
        close(s);
        return err; // bad connect
    }
    return s;
}

int make_tcp_connection(const char * hostname, unsigned short port, int mstimeout)
{
    return make_tcp_connection_from_port(hostname,port, INADDR_ANY, mstimeout);
}

void openflowswitch_set_pollfd(struct pollfd *pfd)
{
    pfd->events = POLLIN|POLLOUT;
    pfd->fd = sock;
}
    
void controller_connect(void)
{
    // Open controller connection
    sock = make_tcp_connection(controller_ip_string, controller_port, 3000);
    sleep(2);
    if(sock < 0 )
    {
        exit(1);
    }
    if (secure_disconnect == 1)
    {
        if (flow_table->iLastFlow != 0) clear_flowtable();
    }
    
    OF_hello();
}

void clear_flowtable(void)
{
    struct ofp13_port_stats temp_port_stats[ETH_PORT_NO];
    memcpy(&temp_port_stats, flow_table->phys13_port_stats, sizeof(struct ofp13_port_stats) * ETH_PORT_NO);
    
    memset(flow_table, 0, FTPAGES * PAGE_SIZE);
    memset(pk_buffer, 0, PBPAGES * PAGE_SIZE);
    memcpy(flow_table->phys13_port_stats, &temp_port_stats, sizeof(struct ofp13_port_stats) * ETH_PORT_NO);
    
    // Set flags
    flow_table->enabled = enabled;
    flow_table->auth_bypass = auth_bypass;
    flow_table->port_status[ETH_PORT_NO-1] = true;  // Set the Ethernet port to UP on startup

}

void clear_mmap(void)
{
    memset(flow_table, 0, FTPAGES * PAGE_SIZE);
    memset(pk_buffer, 0, PBPAGES * PAGE_SIZE);
    
    // Set flags
    flow_table->enabled = enabled;
    flow_table->auth_bypass = auth_bypass;
    flow_table->port_status[ETH_PORT_NO-1] = true;  // Set the Ethernet port to UP on startup
}

int main(int argc, const char * argv[]) {

    struct  pollfd  * pollfds;
    pollfds = malloc(sizeof(struct pollfd));
    assert(pollfds);
    int x;
    int configfd;
    char line[128];
    char *token;
    int token_cnt = 0;
    int opt = 0;        // command line options
    int timer_count = 0;
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;
    uint8_t *dst_ehdr, *src_ehdr;
    char *ifname ="eth0";    // Zodiac WX interface name
    
    outbuf = msgbuf_new(BUFLEN);
    inbuf = msgbuf_new(BUFLEN);
    
    // Load UCI config file
    FILE *file = fopen( "/etc/config/nnofagent", "r" );
    
    if ( file == 0 )
    {
        // No file found
    }
    else
    {
        while(fgets(line, sizeof(line), file) != NULL)
        {
            if(line[0] == '#' || line[0] == '\n') continue;     // Ignore comments
            
            if (strstr(line, "controller_ip") != NULL){
                token = strtok(line, " '\t\n");
                while( token != NULL )
                {
                    if (token_cnt == 2)
                    {
                        strcpy(controller_ip_string, token);
                    }
                    token = strtok(NULL, " '\t\n");
                    token_cnt++;
                }
                token_cnt = 0;
            }
            
            if (strstr(line, "controller_port") != NULL){
                token = strtok(line, " '\t\n");
                while( token != NULL )
                {
                    if (token_cnt == 2)
                    {
                        controller_port = atoi(token);
                    }
                    token = strtok(NULL, " '\t\n");
                    token_cnt++;
                }
                token_cnt = 0;
            }

            if (strstr(line, "enabled") != NULL){
                token = strtok(line, " '\t\n");
                while( token != NULL )
                {
                    if (token_cnt == 2)
                    {
                        enabled = atoi(token);
                    }
                    token = strtok(NULL, " '\t\n");
                    token_cnt++;
                }
                token_cnt = 0;
            }

            if (strstr(line, "auth_bypass") != NULL){
                token = strtok(line, " '\t\n");
                while( token != NULL )
                {
                    if (token_cnt == 2)
                    {
                        auth_bypass = atoi(token);
                        //fprintf("agent.c: Auth Bypass = %d\n", auth_bypass);
                    }
                    token = strtok(NULL, " '\t\n");
                    token_cnt++;
                }
                token_cnt = 0;
            }

            if (strstr(line, "secure") != NULL){
                token = strtok(line, " '\t\n");
                while( token != NULL )
                {
                    if (token_cnt == 2)
                    {
                        secure_disconnect = atoi(token);
                        //printf("agent.c: Secure Disconnect = %d\n", secure_disconnect);
                    }
                    token = strtok(NULL, " '\t\n");
                    token_cnt++;
                }
                token_cnt = 0;
            }
        }
    }
    fclose( file );
    
    configfd = open("/sys/kernel/debug/openflow/data", O_RDWR);
    if(configfd < 0)
    {
        printf("Unable to open mmap file!");
        return -1;
    }
    
    flow_table = mmap(NULL, FTPAGES*PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, configfd, 0);

    if (flow_table == MAP_FAILED)
    {
        printf("mmap operation failed");
        return -1;
    }

    pk_buffer = mmap(NULL, PBPAGES*PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, configfd, FTPAGES*PAGE_SIZE);
    if (pk_buffer == MAP_FAILED)
    {
        printf("mmap operation failed");
        return -1;
    }
    // Initialise time
    current_time = (int)time(NULL);

    // Get MAC Address
    if (getifaddrs(&ifap) == 0)
    {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_PACKET))
            {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
                memcpy(MAC_address, ptr+4, 6);
                break;
            }
        }
        freeifaddrs(ifap);
    }
    
    // Check for arguments
    if(argc > 1)
    {
        while((opt=getopt(argc,argv,"fgmc"))!=-1)
        {
            switch(opt)
            {
                case 'f':
                    // call function
                    print_flows();
                    if(munmap(flow_table, FTPAGES*PAGE_SIZE) !=0)
                    {
                        printf("munmap operation failed for flow_table");
                    }
                    if(munmap(pk_buffer, PBPAGES*PAGE_SIZE) !=0)
                    {
                        printf("munmap operation failed for pk_buffer");
                    }                       
                    return 0;
                case 'g':
                    // show groups
                    print_groups();
                    return 0;
                case 'm':
                    // show meters
                    print_meters();
                    return 0;
                case 'c':
                    // clear flowtable
                    clear_flowtable();
                    return 0;
            }
        }
    }
    
    clear_mmap();      // Clear memory location

    if (enabled == 1) controller_connect();
    
    // Main processing loop
    while(1)
    {
        openflowswitch_set_pollfd(pollfds);
        poll(pollfds, 1, 100);      // block until something is ready or 10ms passes
        openflowswitch_handle_io(pollfds);
        
        if (!sock && enabled == 1) controller_connect();
        
        // Check packet buffer
        for(x=0;x<(PACKET_BUFFER);x++)
        {
            if(pk_buffer->buffer[x].type == PB_PACKETIN)
            {
                dst_ehdr = pk_buffer->buffer[x].buffer;
                src_ehdr = dst_ehdr + 6;

                if (src_ehdr[0] !=0 & src_ehdr[1] !=0 & src_ehdr[2] != 0 & dst_ehdr[0] !=0 & dst_ehdr[1] !=0 & dst_ehdr[2] != 0)
                    {
                        //fprintf(stderr, "agent.c: Sending Packet IN\n");
                        packet_in13(x, pk_buffer->buffer[x].buffer, pk_buffer->buffer[x].size, pk_buffer->buffer[x].inport, pk_buffer->buffer[x].reason, pk_buffer->buffer[x].flow);
                    } else {
                        //fprintf(stderr, "agent.c: Dropping Packet IN, empty header!\n");
                        pk_buffer->buffer[x].type = PB_PENDING;  // Mark as sent
                    }
            }
        }
        usleep(1000);    // Allow CPU to sleep (1ms)
        
        if(timer_count > 500)
        {
            // Housekeeping timer (500 ms)
            of_timer();
            timer_count = 0;
        }
        else
        {
            timer_count++;
        }
    }
    return 0;
}

void print_flows(void)
{
    int i;  // counter
    
    if (flow_table->iLastFlow > 0)
    {
        int match_size;
        int inst_size;
        int act_size;
        struct ofp13_instruction_actions *inst_actions;
        struct oxm_header13 oxm_header;
        
        uint8_t oxm_value8;
        uint16_t oxm_value16;
        uint32_t oxm_value32;
        uint8_t oxm_eth[6];
        uint8_t oxm_ipv4[8];
        uint16_t oxm_ipv6[8];
        for (i=0;i<(flow_table->iLastFlow);i++)
        {
            printf("\r\nFlow %d\r\n",i+1);
            printf(" Match:\r\n");
            match_size = 0;
            while (match_size < (ntohs(flow_table->flow_match13[i].match.length)-4))
            {
                memcpy(&oxm_header, flow_table->ofp13_oxm[i].match + match_size,4);
                int has_mask = oxm_header.oxm_field & 1;        // TODO: adjust to bool
                oxm_header.oxm_field = oxm_header.oxm_field >> 1;
                switch(oxm_header.oxm_field)
                {
                    case OFPXMT_OFB_IN_PORT:
                        memcpy(&oxm_value32, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 4);
                        printf("  In Port: %d\r\n",ntohl(oxm_value32));
                    break;

                    case OFPXMT_OFB_ETH_DST:
                        memcpy(&oxm_eth, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 6);
                        printf("  Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                    break;

                    case OFPXMT_OFB_ETH_SRC:
                        memcpy(&oxm_eth, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 6);
                        printf("  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                    break;

                    case OFPXMT_OFB_ETH_TYPE:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        if (ntohs(oxm_value16) == 0x0806)printf("  ETH Type: ARP\r\n");
                        else if (ntohs(oxm_value16) == 0x0800)printf("  ETH Type: IPv4\r\n");
                        else if (ntohs(oxm_value16) == 0x86dd)printf("  ETH Type: IPv6\r\n");
                        else if (ntohs(oxm_value16) == 0x8100)printf("  ETH Type: VLAN\r\n");
                        else if (ntohs(oxm_value16) == 0x888e)printf("  ETH Type: EAPOL\r\n");
                        else if (ntohs(oxm_value16) == 0x88cc)printf("  ETH Type: LLDP\r\n");
                        else if (ntohs(oxm_value16) == 0x8999)printf("  ETH Type: BDDP\r\n");
                        else if (ntohs(oxm_value16) == 0x9100)printf("  ETH Type: VLAN(D)\r\n");
                        else printf("  ETH Type: 0x%X\r\n", ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_IP_PROTO:
                        memcpy(&oxm_value8, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 1);
                        if (oxm_value8 == 1)printf("  IP Protocol: ICMP\r\n");
                        else if (oxm_value8 == 6)printf("  IP Protocol: TCP\r\n");
                        else if (oxm_value8 == 17)printf("  IP Protocol: UDP\r\n");
                        else printf("  IP Protocol: %d\r\n", oxm_value8);
                    break;

                    case OFPXMT_OFB_IPV4_SRC:
                        if (has_mask)
                        {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 8);
                            printf("  Source IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
                        } else {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 4);
                            printf("  Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                        }
                    break;

                    case OFPXMT_OFB_IPV4_DST:
                        if (has_mask)
                        {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 8);
                            printf("  Destination IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
                        } else {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 4);
                            printf("  Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                        }
                    break;

                    case OFPXMT_OFB_IPV6_SRC:
                        memcpy(&oxm_ipv6, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 16);
                        printf("  Source IP: %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
                    break;

                    case OFPXMT_OFB_IPV6_DST:
                        memcpy(&oxm_ipv6, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 16);
                        printf("  Destination IP:  %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
                    break;

                    case OFPXMT_OFB_TCP_SRC:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        printf("  Source TCP Port: %d\r\n",ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_TCP_DST:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        printf("  Destination TCP Port: %d\r\n",ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_UDP_SRC:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        printf("  Source UDP Port: %d\r\n",ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_UDP_DST:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        printf("  Destination UDP Port: %d\r\n",ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_VLAN_VID:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        if (oxm_value16 != 0) printf("  VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
                    break;

                    case OFPXMT_OFB_ARP_OP:
                        memcpy(&oxm_value16, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 2);
                        if (oxm_value16 == 1) printf("  ARP OP Code: Request (%d)\r\n",ntohs(oxm_value16));
                        if (oxm_value16 == 2) printf("  ARP OP Code: Reply (%d)\r\n",ntohs(oxm_value16));
                    break;

                    case OFPXMT_OFB_ARP_SPA:
                        if (has_mask)
                        {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 8);
                            printf("  Source IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
                        } else {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 4);
                            printf("  Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                        }
                    break;

                    case OFPXMT_OFB_ARP_TPA:
                        if (has_mask)
                        {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 8);
                            printf("  Target IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
                        } else {
                            memcpy(&oxm_ipv4, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 4);
                            printf("  Target IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                        }
                    break;

                    case OFPXMT_OFB_ARP_SHA:
                        memcpy(&oxm_eth, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 6);
                        printf("  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                    break;

                    case OFPXMT_OFB_ARP_THA:
                        memcpy(&oxm_eth, flow_table->ofp13_oxm[i].match + sizeof(struct oxm_header13) + match_size, 6);
                        printf("  Target MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                    break;
                };
                
                match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
            }
            
            if((ntohs(flow_table->flow_match13[i].match.length)-4) == 0) printf("  ANY\r\n");
            
            printf("\r Attributes:\r\n");
            printf("  Table ID: %d\t\t\t\tCookie:0x%x\r\n",flow_table->flow_match13[i].table_id, _htonll(flow_table->flow_match13[i].cookie));
            printf("  Priority: %d\t\t\t\tDuration: %d secs\r\n",ntohs(flow_table->flow_match13[i].priority), current_time - flow_table->flow_counters[i].duration);
            printf("  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n",ntohs(flow_table->flow_match13[i].hard_timeout), ntohs(flow_table->flow_match13[i].idle_timeout));
            printf("  Byte Count: %" PRIu64 "\t\t\tPacket Count: %" PRIu64 "\r\n",flow_table->flow_counters[i].bytes, flow_table->flow_counters[i].hitCount);
            int lm = current_time - flow_table->flow_counters[i].lastmatch;
            printf("  Last Match: %d secs\r\n", lm);

            // Print instruction list
            if (flow_table->ofp13_oxm[i].inst != NULL)
            {
                // Get a list of all instructions for this flow
                void *insts[8] = {0};
                inst_size = 0;
                while(inst_size < flow_table->ofp13_oxm[i].inst_size){
                    struct ofp13_instruction *inst_ptr = (struct ofp13_instruction *)(flow_table->ofp13_oxm[i].inst + inst_size);
                    insts[ntohs(inst_ptr->type)] = inst_ptr;
                    inst_size += ntohs(inst_ptr->len);
                }
        
                printf("\r Instructions:\r\n");
                
                // Check for optional metering instruction
                if(insts[OFPIT13_METER] != NULL)						
                {
                    struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
                    printf("  Meter: %d\r\n", ntohl(inst_meter->meter_id));
                }
                
                if(insts[OFPIT13_APPLY_ACTIONS] != NULL)
                {
                    printf("  Actions:\r\n");
                    struct ofp13_action_header *act_hdr;
                    act_size = 0;
                    inst_actions = insts[OFPIT13_APPLY_ACTIONS];
                    if (ntohs(inst_actions->len) == sizeof(struct ofp13_instruction_actions)) printf("   DROP \r\n");	// No actions
                    while (act_size < (ntohs(inst_actions->len) - sizeof(struct ofp13_instruction_actions)))
                    {
                        act_hdr = (struct ofp13_action_header*)((uintptr_t)inst_actions->actions + act_size);
                        if (htons(act_hdr->type) == OFPAT13_OUTPUT)
                        {
                            struct ofp13_action_output *act_output = act_hdr;
                            if (htonl(act_output->port) < OFPP13_MAX)
                            {
                                printf("   Output Port: %d\r\n", htonl(act_output->port));
                            } else if (htonl(act_output->port) == OFPP13_IN_PORT)
                            {
                                printf("   Output Port: IN_PORT \r\n");
                            } else if (htonl(act_output->port) == OFPP13_FLOOD)
                            {
                                printf("   Output Port: FLOOD \r\n");
                            } else if (htonl(act_output->port) == OFPP13_ALL)
                            {
                                printf("   Output Port: ALL \r\n");
                            } else if (htonl(act_output->port) == OFPP13_CONTROLLER)
                            {
                                printf("   Output Port: CONTROLLER \r\n");
                            } else if (htonl(act_output->port) == OFPP13_NORMAL)
                            {
                                printf("   Output Port: NORMAL \r\n");
                            }
                            act_output = NULL;
                        }
                        if (htons(act_hdr->type) == OFPAT13_SET_FIELD)
                        {
                            struct ofp13_action_set_field *act_set_field = act_hdr;
                            memcpy(&oxm_header, act_set_field->field,4);
                            oxm_header.oxm_field = oxm_header.oxm_field >> 1;
                            switch(oxm_header.oxm_field)
                            {
                                case OFPXMT_OFB_VLAN_VID:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
                                break;
                                case OFPXMT_OFB_ETH_SRC:
                                memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
                                printf("   Set Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                                break;
                                case OFPXMT_OFB_ETH_DST:
                                memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
                                printf("   Set Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                                break;
                                case OFPXMT_OFB_ETH_TYPE:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                if (ntohs(oxm_value16) == 0x0806 )printf("   Set ETH Type: ARP\r\n");
                                if (ntohs(oxm_value16) == 0x0800 )printf("   Set ETH Type: IPv4\r\n");
                                if (ntohs(oxm_value16) == 0x86dd )printf("   Set ETH Type: IPv6\r\n");
                                if (ntohs(oxm_value16) == 0x8100 )printf("   Set ETH Type: VLAN\r\n");
                                break;
                                case OFPXMT_OFB_IPV4_SRC:
                                memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
                                printf("   Set Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                                break;
                                case OFPXMT_OFB_IP_PROTO:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                if (oxm_value16 == 1)printf("   Set IP Protocol: ICMP\r\n");
                                if (oxm_value16 == 6)printf("   Set IP Protocol: TCP\r\n");
                                if (oxm_value16 == 17)printf("   Set IP Protocol: UDP\r\n");
                                break;
                                case OFPXMT_OFB_IPV4_DST:
                                memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
                                printf("   Set Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                                break;
                                case OFPXMT_OFB_TCP_SRC:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set TCP Source Port:  %d\r\n", ntohs(oxm_value16));
                                break;
                                case OFPXMT_OFB_TCP_DST:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set TCP Destination Port:  %d\r\n", ntohs(oxm_value16));
                                break;
                                case OFPXMT_OFB_UDP_SRC:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set UDP Source Port:  %d\r\n", ntohs(oxm_value16));
                                break;
                                case OFPXMT_OFB_UDP_DST:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set UDP Destination Port:  %d\r\n", ntohs(oxm_value16));
                                break;
                                case OFPXMT_OFB_ICMPV4_TYPE:
                                memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
                                printf("   Set ICMP Type:  %d\r\n", oxm_value8);
                                break;
                                case OFPXMT_OFB_ICMPV4_CODE:
                                memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
                                printf("   Set ICMP Code:  %d\r\n", oxm_value8);
                                break;
                                case OFPXMT_OFB_ARP_OP:
                                memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
                                printf("   Set ARP OP Code:  %d\r\n", ntohs(oxm_value16));
                                break;
                                case OFPXMT_OFB_ARP_SPA:
                                memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
                                printf("   Set ARP Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                                break;
                                case OFPXMT_OFB_ARP_TPA:
                                memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
                                printf("   Set ARP Target IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
                                break;
                                case OFPXMT_OFB_ARP_SHA:
                                memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
                                printf("   Set ARP Source HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                                break;
                                case OFPXMT_OFB_ARP_THA:
                                memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
                                printf("   Set ARP Target HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
                                break;
                            };
                        }
                        if (htons(act_hdr->type) == OFPAT13_PUSH_VLAN)
                        {
                            struct ofp13_action_push *act_push = act_hdr;
                            printf("   Push VLAN tag\r\n");
                        }
                        if (htons(act_hdr->type) == OFPAT13_POP_VLAN)
                        {
                            printf("   Pop VLAN tag\r\n");
                        }
                        if (htons(act_hdr->type) == OFPAT13_GROUP)
                        {
                            struct ofp13_action_group *act_group = act_hdr;
                            printf("   Apply Group: %d\r\n", htonl(act_group->group_id));
                        }
                        act_size += htons(act_hdr->len);
                    }
                    }
                // Print goto table instruction
                if(insts[OFPIT13_GOTO_TABLE] != NULL)
                {
                    struct ofp13_instruction_goto_table *inst_goto_ptr;
                    inst_goto_ptr = (struct ofp13_instruction_goto_table *) insts[OFPIT13_GOTO_TABLE];
                    printf("  Goto Table: %d\r\n", inst_goto_ptr->table_id);
                }
            }
            else
            {
                // No instructions
                printf("\r Instructions:\r\n");
                printf("   DROP \r\n");
            }
        }
    }
    else
    {
        printf("No flows installed\r\n");
    }
    
    return;
}

void print_meters(void)
{
    int meter_out_counter = 1;
    
    // Check that table is populated
    if(flow_table->meter_table.meter_entry[0].active == 1)
    {
        int meter_index = 0;
        while(flow_table->meter_table.meter_entry[meter_index].active == 1 && meter_index < MAX_METER_13)
        {
            printf("\r\nMeter %d\r\n", meter_out_counter);
            meter_out_counter++;
            printf("  Meter ID: %d\r\n", flow_table->meter_table.meter_entry[meter_index].meter_id);
            printf("  Counters:\r\n");
            flow_table->meter_table.meter_entry[meter_index].flow_count = get_bound_flows(flow_table->meter_table.meter_entry[meter_index].meter_id);
            printf("\tBound Flows:\t%d\tDuration:\t%d sec\r\n", flow_table->meter_table.meter_entry[meter_index].flow_count, (current_time-flow_table->meter_table.meter_entry[meter_index].time_added));
            printf("\tByte Count:\t%llu\tPacket Count:\t%llu\r\n", flow_table->meter_table.meter_entry[meter_index].byte_in_count, flow_table->meter_table.meter_entry[meter_index].packet_in_count);
            printf("\tConfiguration:\t");
            if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_KBPS) == OFPMF13_KBPS)
            {
                printf("KBPS; ");
            }
            if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_PKTPS) == OFPMF13_PKTPS)
            {
                printf("PKTPS; ");
            }
            if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_BURST) == OFPMF13_BURST)
            {
                printf("BURST; ");
            }
            if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_STATS) == OFPMF13_STATS)
            {
                printf("STATS; ");
            }
            if(flow_table->meter_table.meter_entry[meter_index].flags == 0)
            {
                printf(" NONE;");
            }
            
            printf("\r\n\tNumber of bands:\t%d\r\n", flow_table->meter_table.meter_entry[meter_index].band_count);
            int bands_processed = 0;
            struct ofp13_meter_band_drop * ptr_band;
            ptr_band = &(flow_table->meter_table.meter_entry[meter_index].bands[0]);
            while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
            {
                printf("\t\tBand %d:\r\n", bands_processed+1);
                printf("\t\t  Type:\t\t");
                if(ptr_band->type == OFPMBT13_DROP)
                {
                    printf("DROP\r\n");
                }
                else if(ptr_band->type == OFPMBT13_DSCP_REMARK)
                {
                    printf("DSCP REMARK\r\n");
                }
                else
                {
                    printf("unsupported type\r\n");
                }
                printf("\t\t  Rate:\t\t%d\t\r\n", ptr_band->rate);
                printf("\t\t  Burst Size:\t%d\t\r\n", ptr_band->burst_size);
                
                if(ptr_band->type == OFPMBT13_DSCP_REMARK)
                {
                    printf("\t\t  Precedence:\t+%d\t\r\n", ((struct ofp13_meter_band_dscp_remark*)ptr_band)->prec_level);
                }
                
                // Find band index
                int band_index = (int)((uint8_t*)ptr_band - (uint8_t*)&(flow_table->meter_table.meter_entry[meter_index].bands)) / sizeof(struct ofp13_meter_band_drop);
                
                // Display counters
                printf("\t\t  Byte count:\t%llu\t\r\n", flow_table->meter_table.band_stats_array[meter_index].band_stats[band_index].byte_band_count);
                printf("\t\t  Packet count:\t%llu\t\r\n", flow_table->meter_table.band_stats_array[meter_index].band_stats[band_index].packet_band_count);
                
                ptr_band++;	// Move to next band
                bands_processed++;
            }
            meter_index++;
        }
    }
    else
    {
        printf("No meters configured.\r\n");
    }
    return;
}

void print_groups(void)
{
    int g;
    bool no_groups = true;
    
    // Find first empty group entry
    for(g=0;g<MAX_GROUPS;g++)
    {
        if (flow_table->group_table[g].active == true)
        {
            no_groups = false;
            printf("\r\nGroup %d\r\n", g+1);
            printf("  Group ID: %d\r\n", flow_table->group_table[g].group_id);
            if (flow_table->group_table[g].type == OFPGT13_ALL) printf("  Type: ALL\r\n");
            if (flow_table->group_table[g].type == OFPGT13_SELECT) printf("  Type: SELECT\r\n");
            if (flow_table->group_table[g].type == OFPGT13_INDIRECT) printf("  Type: INDIRECT\r\n");
            if (flow_table->group_table[g].type == OFPGT13_FF) printf("  Type: FAST FAILOVER\r\n");
            printf("  Actions:\r\n");
            
            struct ofp13_bucket *bucket_hdr;
            bucket_hdr = (struct ofp13_bucket *)flow_table->action_buckets[flow_table->group_table[g].bucket_id-1].data;
            struct ofp13_action_header *act_hdr;
            uint8_t act_size = sizeof(struct ofp13_bucket);
            if (htons(bucket_hdr->len == sizeof(struct ofp13_bucket))) printf("   DROP \r\n");	// No actions
            
            while (act_size < htons(bucket_hdr->len))
            {
                act_hdr = (struct ofp13_action_header*)((uintptr_t)bucket_hdr + act_size);
                if (htons(act_hdr->type) == OFPAT13_OUTPUT)
                {
                    struct ofp13_action_output *act_output = act_hdr;
                    if (htonl(act_output->port) < OFPP13_MAX)
                    {
                        printf("   Output Port: %d\r\n", htonl(act_output->port));
                    } else if (htonl(act_output->port) == OFPP13_IN_PORT)
                    {
                        printf("   Output: IN_PORT \r\n");
                    } else if (htonl(act_output->port) == OFPP13_FLOOD)
                    {
                        printf("   Output: FLOOD \r\n");
                    } else if (htonl(act_output->port) == OFPP13_ALL)
                    {
                        printf("   Output: ALL \r\n");
                    } else if (htonl(act_output->port) == OFPP13_CONTROLLER)
                    {
                        printf("   Output: CONTROLLER \r\n");
                    } else if (htonl(act_output->port) == OFPP13_NORMAL)
                    {
                        printf("   Output: NORMAL \r\n");
                    }
                }
                act_size += htons(act_hdr->len);
            }
        }
    }
    if (no_groups == true) printf("No groups configured.\r\n");
    return;
}
