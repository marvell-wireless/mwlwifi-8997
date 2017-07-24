/*
 * Command implementations
 */
#include <errno.h>
#include "mwlutl.h"

/* copied from the kernel -- keep in sync */
enum mwl_testmode_attr {
	MWL_TM_ATTR_CMD	= 1,
	MWL_TM_ATTR_DUMP_OTP	= 2,

	/* keep last */
	__MWL_TM_ATTR_AFTER_LAST,
	MWL_TM_ATTR_MAX	= __MWL_TM_ATTR_AFTER_LAST - 1
};

enum mwl_testmode_cmd {
	MWL_TM_CMD_UNSPEC	= 0,
	MWL_TM_CMD_DUMP_OTP	= 1,
	MWL_TM_CMD_DUTY_CYC_TX	= 2,
};


/* code to do everything */

#if 0
static int print_ps(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *td[HWSIM_TM_ATTR_MAX + 1];

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_TESTDATA] || !tb[NL80211_ATTR_WIPHY]) {
		printf("no data!\n");
		return NL_SKIP;
	}

	nla_parse(td, HWSIM_TM_ATTR_MAX, nla_data(tb[NL80211_ATTR_TESTDATA]),
		  nla_len(tb[NL80211_ATTR_TESTDATA]), NULL);

	if (!td[HWSIM_TM_ATTR_PS]) {
		printf("no PS info\n");
		return NL_SKIP;
	}

	printf("phy#%d ps %d\n",
		nla_get_u32(tb[NL80211_ATTR_WIPHY]),
		nla_get_u32(td[HWSIM_TM_ATTR_PS]));

	return NL_SKIP;
}

static int do_ps(struct nl_cb *cb, struct nl_msg *msg, int argc, char **argv)
{
	if (argc >= 2)
		return 3;


	if (argc == 0) {
		NLA_PUT_U32(msg, HWSIM_TM_ATTR_CMD, HWSIM_TM_CMD_GET_PS);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_ps, NULL);
		return 0;
	}

	NLA_PUT_U32(msg, HWSIM_TM_ATTR_CMD, HWSIM_TM_CMD_SET_PS);
	NLA_PUT_U32(msg, HWSIM_TM_ATTR_PS, atoi(*argv));

	return 0;

 nla_put_failure:
	return -ENOBUFS;
}
#endif

static int print_otp(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *td[MWL_TM_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

//	printf("%s() called max=%d msglen=%d\n", __FUNCTION__, NL80211_ATTR_MAX, genlmsg_attrlen(gnlh, 0));

#if 0
	print_hex( genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0));
#endif

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

#if 0
{
	int i;
	for (i=0;i<=NL80211_ATTR_MAX; i++) {
			if(tb[i])
				printf("Attr: %d present\n", i);
	}
}

	printf("Idx Tdata=%d wiphy=%d\n", NL80211_ATTR_TESTDATA,
			NL80211_ATTR_WIPHY);

	printf("tb Tdata=%p wiphy=%p\n", tb[NL80211_ATTR_TESTDATA],
			tb[NL80211_ATTR_WIPHY]);
#endif

	if (!tb[NL80211_ATTR_TESTDATA] || 
			!tb[NL80211_ATTR_WIPHY]) {
		printf("no data!\n");
		return NL_SKIP;
	}

	nla_parse(td, MWL_TM_ATTR_MAX, nla_data(tb[NL80211_ATTR_TESTDATA]),
		  nla_len(tb[NL80211_ATTR_TESTDATA]), NULL);

	if (!td[MWL_TM_ATTR_DUMP_OTP]) {
		printf("no OTP dump\n");
		return NL_SKIP;
	}

	print_hex(nla_data(td[MWL_TM_ATTR_DUMP_OTP]), 
			nla_len(td[MWL_TM_ATTR_DUMP_OTP]));


	return NL_SKIP;
}

static int do_dump_otp(struct nl_cb *cb, struct nl_msg *msg, int argc, char **argv)
{
	NLA_PUT_U32(msg, MWL_TM_ATTR_CMD, MWL_TM_CMD_DUMP_OTP);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_otp, NULL);
	return 0;

 nla_put_failure:
	return -ENOBUFS;
}

typedef struct duty_cyc_tx_cfg {
} duty_cyc_tx_cfg_t;

static int do_duty_cyc_tx(struct nl_cb *cb, struct nl_msg *msg, int argc, char **argv)
{
	NLA_PUT_U32(msg, MWL_TM_ATTR_CMD, MWL_TM_CMD_DUTY_CYC_TX);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_otp, NULL);
	return 0;

 nla_put_failure:
	return -ENOBUFS;
}


int do_commands(struct nl_cb *cb, struct nl_msg *msg, int argc, char **argv)
{
	if (argc <= 0){
		printf("Command List:\n");
		printf("mwlutl <phy#> <dump_otp>\n");
		printf("mwlutl <phy#> <duty_cyc_tx>\n");
		return 3;
	}

	if (strcmp(*argv, "dump_otp") == 0)
		return do_dump_otp(cb, msg, argc - 1, argv + 1);
	if (strcmp(*argv, "duty_cyc_tx") == 0)
		return do_duty_cyc_tx(cb, msg, argc - 1, argv + 1);

	return 1;
}
