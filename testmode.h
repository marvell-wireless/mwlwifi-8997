#ifndef _TESTMODE_H_
#define _TESTMODE_H_

int mwl_mac80211_testmode_cmd(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       void *data, int len);

#endif	//_TESTMODE_H_
