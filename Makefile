CC = cc
CFLAGS = -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -O2
LDFLAGS = -lpam -lpam_misc

SRC = asroot.c config.c pam.c
BUILDDIR = build
OBJ = $(SRC:%.c=$(BUILDDIR)/%.o)
BIN = $(BUILDDIR)/asroot

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(BUILDDIR)
	$(CC) -c $(CFLAGS) $< -o $@

install: $(BIN)
	install -Dm4755 $(BIN) $(DESTDIR)$(BINDIR)/asroot
	install -Dm644 asroot.1 $(DESTDIR)$(MANDIR)/asroot.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/asroot
	rm -f $(DESTDIR)$(MANDIR)/asroot.1

clean:
	rm -rf $(BUILDDIR)

.PHONY: all install uninstall clean
