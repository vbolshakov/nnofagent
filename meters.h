//
//  meters.h
//  nnofagent
//
//  Created by Paul Zanna on 26/8/17.
//  Copyright © 2017 Northbound Networks. All rights reserved.
//

int multi_meter_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_meter_config_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_meter_features_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);

// Mod functions
void meter_mod13(struct ofp_header *msg);
void meter_add13(struct ofp_header *msg);
void meter_modify13(struct ofp_header *msg);
void meter_delete13(struct ofp_header *msg);
