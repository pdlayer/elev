# Maintainer: pdlayer
pkgname=asroot
pkgver=0.1
pkgrel=1
pkgdesc="sudo sucks."
arch=('x86_64')
license=('ISC')
depends=('pam')
makedepends=('gcc' 'make')
source=('../asroot.c' '../config.c' '../pam.c' '../asroot.h' '../asroot.1' '../Makefile')
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
	cd "$srcdir/../"
	make
}

package() {
	cd "$srcdir/../"
	
	# Use Makefile install target
	make DESTDIR="$pkgdir" PREFIX="/usr" install
	
	# Create config directory
	install -dm700 "$pkgdir/etc/asroot"
	
	# Create default PAM config for Arch
	mkdir -p "$pkgdir/etc/pam.d"
	cat > "$pkgdir/etc/pam.d/asroot" <<EOF
auth        include     system-auth
account     include     system-auth
session     include     system-auth
EOF
}
