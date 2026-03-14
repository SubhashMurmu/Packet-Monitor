/*SPDX-License-Identifier: GPL-2.0*/

#ifndef PACKET_MONITOR_H
#define PACKET_MONITOR_H

#define PM_MAX_FILTER_RULES   64
#define PM_MAX_TOP_IPS        10
#define PM_PROC_STATS         "packet_monitor"
#define PM_PROC_FILTER        "packet_filter"
#define PM_FILTER_BUF_SZ      128

#define PM_RULE_BLOCK  0
#define PM_RULE_ALLOW  1

#define PM_MODE_BLACKLIST  0
#define PM_MODE_WHITELIST  1

#endif 
