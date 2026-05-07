pkgname=elev
pkgver=1.0.0
pkgrel=1
pkgdesc="sudo sucks."
arch=('x86_64')
license=('BSD')
depends=('pam')
makedepends=('gcc' 'meson' 'ninja')
install=elev.install
source=('elev.c' 'config.c' 'pam.c' 'util.c' 'elev.h' 'elev.1' 'elev.5' 'elev.7' 'meson.build' 'meson_options.txt' 'elev.bash' 'elev.zsh' 'elev.install' 'elev.pam')
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
	meson setup builddir --prefix=/usr
	meson compile -C builddir
}

package() {
	DESTDIR="$pkgdir" meson install -C builddir
	
	install -dm700 "$pkgdir/etc/elev"
}
