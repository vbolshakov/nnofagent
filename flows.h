//
//  flows.h
//  nnofagent
//
//  Created by Paul Zanna on 26/8/17.
//  Copyright © 2017 Northbound Networks. All rights reserved.
//

#include <stdio.h>

void flow_mod13(struct ofp_header *msg);
void flow_add13(struct ofp_header *msg);
void flow_delete13(struct ofp_header *msg);
void flow_delete_strict13(struct ofp_header *msg);
int flow_stats_msg13(char *buffer, int first, int last);
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
