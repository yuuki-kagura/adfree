# Arch Linux, CachyOS (and other derivatives)

CachyOS is an Arch derivative, so the same package serves both: there is no
separate build, repository or flag. What differs is only where a user gets it.

## From a release

Every release attaches `adfree-<version>-1-x86_64.pkg.tar.zst` (and, from the
ARM job, a `.deb`/`.rpm` for Arch ARM users to build against). Install it with
the one thing pacman understands:

```sh
sudo pacman -U adfree-1.4.0-1-x86_64.pkg.tar.zst
```

That is the whole install: the app image carries its own runtime, so nothing
from the repositories is pulled in except `gcc-libs`.

## From source

```sh
git clone --depth 1 --branch v1.4.0 https://github.com/yuuki-kagura/adfree
cd adfree/packaging/arch
makepkg -si
```

`makepkg` compiles the filtering core (`cargo build --release --lib`) and then
lets Gradle lay out the app image. Two details in this PKGBUILD are there
because getting them wrong fails quietly:

- The Rust build runs with `CFLAGS`, `CXXFLAGS`, `LDFLAGS` and `RUSTFLAGS`
  cleared. On an LTO-enabled system makepkg's hardening flags include `-flto`,
  the bundled sqlite is then compiled to bitcode, and rustc's link — which never
  sees `LDFLAGS` — leaves that bitcode out. The core still links (a `cdylib` may
  have undefined symbols) and the only symptom is an app that cannot open it.
- `nm` and `ldd -r` check the result: sqlite has to be inside the core, and
  nothing may be undefined. Both are cheap and both catch the failure above.

## Architecture notes

- `arch=('x86_64' 'aarch64')`: on Arch ARM the same tarball builds natively.
  The release artifacts for ARM ship as `.deb`/`.rpm` because jpackage cannot
  cross-build, but `makepkg` on the machine has no such limit.
- CachyOS's `x86-64-v3`/`v4` repositories do not affect this package. The only
  native code it installs is the core, which is compiled on the installing
  machine (or by CI for plain `x86_64`), and the app image's JRE is bundled —
  there is no v3-only object to mismatch.

## Not published to the AUR

The package is reproducible from this directory alone. If it is uploaded, it is
uploaded by whoever maintains that account, with the same two files
(`PKGBUILD`, `.SRCINFO`) — nothing here assumes a maintainer name.
