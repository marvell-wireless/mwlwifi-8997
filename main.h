#ifndef _MAIN_H_
#define _MAIN_H_

#define MWL_DESC         "Marvell 802.11ac Wireless Network Driver"

int mwl_add_card(void *, struct mwl_if_ops *);
void mwl_wl_deinit(struct mwl_priv *);


#endif
