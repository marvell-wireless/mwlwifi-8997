#ifndef __MWLUTL_H
#define __MWLUTL_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include "nl80211.h"

#define ETH_ALEN 6

#ifndef CONFIG_LIBNL20
#  define nl_sock nl_handle
#endif

struct nl80211_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};

int do_commands(struct nl_cb *cb, struct nl_msg *msg, int argc, char **argv);
void print_hex(unsigned char *buf, int len);

#endif /* __MWLUTL_H */
