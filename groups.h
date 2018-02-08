//
//  groups.h
//  nnofagent
//
//  Created by Paul Zanna on 26/8/17.
//  Copyright © 2017 Northbound Networks. All rights reserved.
//


void group_mod13(struct ofp_header *msg);
void group_add13(struct ofp_header *msg);
void group_modify13(struct ofp_header *msg);
void group_delete13(struct ofp_header *msg);

int multi_group_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_group_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_group_features_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
