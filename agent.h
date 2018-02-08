/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <netinet/in.h>

#define BUFLEN 65536

#define PB_EMPTY 0
#define PB_PACKETIN 1
#define PB_PACKETOUT 2
#define PB_PENDING 3

#define VERSION 0.3

#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))
#define	AF_LINK		18		/* Link layer interface */

void clear_flowtable(void);

struct sockaddr_dl {
    u_char	sdl_len;	/* Total length of sockaddr */
    u_char	sdl_family;	/* AF_DLI */
    u_short	sdl_index;	/* if != 0, system given index for interface */
    u_char	sdl_type;	/* interface type */
    u_char	sdl_nlen;	/* interface name length, no trailing 0 reqd. */
    u_char	sdl_alen;	/* link level address length */
    u_char	sdl_slen;	/* link layer selector length */
    char	sdl_data[12];	/* minimum work area, can be larger;
                             contains both if name and ll address */
};
