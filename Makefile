CC = cc
CFLAGS = -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -O2
LDFLAGS = -lpam -lpam_misc

SRC = elev.c config.c pam.c
BUILDDIR = build
OBJ = $(SRC:%.c=$(BUILDDIR)/%.o)
BIN = $(BUILDDIR)/elev

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MAN1DIR = $(PREFIX)/share/man/man1
MAN5DIR = $(PREFIX)/share/man/man5
BASHCOMPDIR = $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR = $(PREFIX)/share/zsh/site-functions
PAMDIR = /etc/pam.d

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(BUILDDIR)
	$(CC) -c $(CFLAGS) $< -o $@

install: $(BIN)
	install -Dm4755 $(BIN) $(DESTDIR)$(BINDIR)/elev
	install -Dm644 elev.1 $(DESTDIR)$(MAN1DIR)/elev.1
	install -Dm644 elev.5 $(DESTDIR)$(MAN5DIR)/elev.5
	install -Dm644 elev.bash $(DESTDIR)$(BASHCOMPDIR)/elev
	install -Dm644 elev.zsh $(DESTDIR)$(ZSHCOMPDIR)/_elev
	install -Dm644 elev.pam $(DESTDIR)$(PAMDIR)/elev

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/elev
	rm -f $(DESTDIR)$(MAN1DIR)/elev.1
	rm -f $(DESTDIR)$(MAN5DIR)/elev.5
	rm -f $(DESTDIR)$(BASHCOMPDIR)/elev
	rm -f $(DESTDIR)$(ZSHCOMPDIR)/_elev
	rm -f $(DESTDIR)$(PAMDIR)/elev

clean:
	rm -rf $(BUILDDIR)

.PHONY: all install uninstall clean
