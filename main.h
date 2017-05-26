#ifndef _MAIN_H_
#define _MAIN_H_

/* WMM Turbo mode */
extern int wmm_turbo;

extern int EDMAC_Ctrl;

#define MWL_DESC         "Marvell 802.11ac Wireless Network Driver"

int mwl_add_card(void *, struct mwl_if_ops *);
void mwl_wl_deinit(struct mwl_priv *);
void mwl_set_caps(struct mwl_priv *priv);


#endif
