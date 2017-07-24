
#include <net/genetlink.h>
#include <net/mac80211.h>

#include "sysadpt.h"
#include "dev.h"


/* These enums need to be kept in sync with userspace */
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

#define MWL_TM_MAX_DATA_LENGTH 	(1000)

static const struct nla_policy mwl_testmode_policy[MWL_TM_ATTR_MAX + 1] = {
	[MWL_TM_ATTR_CMD] = { .type = NLA_U32 },
	[MWL_TM_ATTR_DUMP_OTP] ={ .type = NLA_BINARY,
				  .len = MWL_TM_MAX_DATA_LENGTH },

};

int mwl_mac80211_testmode_cmd(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       void *data, int len)
{
	struct mwl_priv *priv = (struct mwl_priv *) hw->priv;
	struct nlattr *tb[MWL_TM_ATTR_MAX + 1];
	struct sk_buff *skb;
	int ret;

	ret = nla_parse(tb, MWL_TM_ATTR_MAX, data, len,
			mwl_testmode_policy);
	if (ret)
		return ret;

	if (!tb[MWL_TM_ATTR_CMD])
		return -EINVAL;

	switch (nla_get_u32(tb[MWL_TM_ATTR_CMD])) {
	case MWL_TM_CMD_DUMP_OTP:
		wiphy_err(hw->wiphy, "TM_CMD_DUMP_OTP\n");

		skb = cfg80211_testmode_alloc_reply_skb(hw->wiphy,
				nla_total_size(priv->otp_data.len));
		if (!skb)
			return -ENOMEM;

		if (nla_put(skb, MWL_TM_ATTR_DUMP_OTP,
					priv->otp_data.len,
					priv->otp_data.buf))
			goto nla_put_failure;

		ret = cfg80211_testmode_reply(skb);
		break;

	case MWL_TM_CMD_DUTY_CYC_TX:
		wiphy_err(hw->wiphy, "TM_CMD_DUTY_CYC_TX\n");
		break;
	}

	return ret;

 nla_put_failure:
	wiphy_err(hw->wiphy, "%s(): nla_put_failure\n", __FUNCTION__);
	kfree_skb(skb);
	return -ENOBUFS;
}
