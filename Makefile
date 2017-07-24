obj-m += mwlwifi_comm.o

mwlwifi_comm-objs		+= main.o
mwlwifi_comm-objs		+= mac80211.o
mwlwifi_comm-objs		+= fwdl.o
mwlwifi_comm-objs		+= fwcmd.o
mwlwifi_comm-objs		+= tx.o
mwlwifi_comm-objs		+= rx.o
mwlwifi_comm-objs		+= isr.o
mwlwifi_comm-$(CONFIG_THERMAL)	+= thermal.o
mwlwifi_comm-$(CONFIG_DEBUG_FS)	+= debugfs.o
mwlwifi_comm-$(CONFIG_NL80211_TESTMODE)	+= testmode.o
ifeq (1, $(BUILD_MFG))
mwlwifi_comm-objs += mfg.o
endif

mwlwifi_pcie-y += pcie.o
mwlwifi_pcie-y += pfu.o
mwlwifi_sdio-y += sdio.o
#obj-$(CONFIG_MWLWIFI_PCIE) += mwlwifi_pcie.o
obj-m += mwlwifi_pcie.o
obj-m += mwlwifi_sdio.o


AS		= $(CROSS_COMPILE)as
LD		= $(CROSS_COMPILE)ld
CC		= $(CROSS_COMPILE)gcc

EXTRA_CFLAGS+= -I${KDIR}
EXTRA_CFLAGS+= -O2 -funroll-loops -D__CHECK_ENDIAN__

EXTRA_CFLAGS+= -g -ggdb

ifeq (1, $(BUILD_MFG))
EXTRA_CFLAGS+= -DSUPPORT_MFG
endif

ifeq (1, $(BUILD_BG4CT_A0))
EXTRA_CFLAGS+= -DBG4CT_A0_WORKAROUND
endif

EXTRA_CFLAGS+= -I${PWD}

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -f *.o *.a *.s *.ko *.ko.cmd *.o.cmd *.mod.* .mwlwifi.*
	rm -rf modules.order Module.symvers .tmp_versions
	find . -name ".*.o.cmd" -exec rm -f {} \;
