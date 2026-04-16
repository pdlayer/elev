# Maintainer: pdlayer
pkgname=elev
pkgver=0.1
pkgrel=1
pkgdesc="sudo sucks."
arch=('x86_64')
license=('ISC')
depends=('pam')
makedepends=('gcc' 'make')
source=('elev.c' 'config.c' 'pam.c' 'elev.h' 'elev.1' 'Makefile' 'elev.bash' 'elev.zsh')
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
	make
}

package() {
	make DESTDIR="$pkgdir" PREFIX="/usr" install
	
	# Create config directory
	install -dm700 "$pkgdir/etc/elev"
	
	# Create default PAM config for Arch
	mkdir -p "$pkgdir/etc/pam.d"
	cat > "$pkgdir/etc/pam.d/elev" <<EOF
auth        include     system-auth
account     include     system-auth
session     include     system-auth
EOF
}
