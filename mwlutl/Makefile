MAKEFLAGS += --no-print-directory

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
PKG_CONFIG ?= pkg-config

MKDIR ?= mkdir -p
CC ?= "gcc"

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration

OBJS = mwlutl.o cmd.o
ALL = mwlutl

NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
NL2FOUND := $(shell $(PKG_CONFIG) --atleast-version=2 libnl-2.0 && echo Y)

ifeq ($(NL1FOUND),Y)
NLLIBNAME = libnl-1
endif

ifeq ($(NL2FOUND),Y)
CFLAGS += -DCONFIG_LIBNL20
LIBS += -lnl-genl
NLLIBNAME = libnl-2.0
endif

ifeq ($(NLLIBNAME),)
$(error Cannot find development files for any supported version of libnl)
endif

LIBS += $(shell pkg-config --libs $(NLLIBNAME))
CFLAGS += $(shell pkg-config --cflags $(NLLIBNAME))

ifeq ($(V),1)
Q=
NQ=true
else
Q=@
NQ=echo
endif

all: version_check $(ALL)

version_check:
ifeq ($(NL2FOUND),Y)
else
ifeq ($(NL1FOUND),Y)
else
	$(error No libnl found)
endif
endif


%.o: %.c nl80211.h
	@$(NQ) ' CC  ' $@
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

mwlutl:	$(OBJS)
	@$(NQ) ' CC  ' mwlutl
	$(Q)$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o mwlutl

check:
	$(Q)$(MAKE) all CC="REAL_CC=$(CC) CHECK=\"sparse -Wall\" cgcc"

clean:
	$(Q)rm -f mwlutl *.o *~
