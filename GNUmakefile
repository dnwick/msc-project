# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	server server-b
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/serverFileTransfer

NO_MAN=
#CFLAGS = -O2 -pipe
CFLAGS = -O3
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include -I $(SRCDIR)/libnetmap
CFLAGS += -Wextra -Wno-address-of-packed-member

LDFLAGS = -L $(BUILDDIR)/build-libnetmap
LDLIBS += -lpthread -lm -lnetmap
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

ifdef WITH_PCAP
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
	-install -D -m 644 $(SRCDIR)/netmap-server/netmap-server.8 $(DESTDIR)/$(MAN_PREFIX)/man8/server.8

server-b: server-b.o

server-b.o: server.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $^ -o $@
