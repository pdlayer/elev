pkgname=elev
pkgver=1.0.0
pkgrel=1
pkgdesc="sudo sucks."
arch=('x86_64')
license=('ISC')
depends=('pam')
makedepends=('gcc' 'make')
install=elev.install
source=('elev.c' 'config.c' 'pam.c' 'util.c' 'elev.h' 'elev.1' 'elev.5' 'elev.7' 'Makefile' 'elev.bash' 'elev.zsh' 'elev.install' 'elev.pam')
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
	make
}

package() {
	make DESTDIR="$pkgdir" PREFIX="/usr" install
	
	install -dm700 "$pkgdir/etc/elev"
}
