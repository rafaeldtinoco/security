#!/usr/bin/env python3
"""
compile.py — self-contained DirtyCBC build helper.

Sets up a local ./src/ tree that contains everything needed to
build poc.c without any system-wide package install, and builds
the PoC against it.

Usage:
    ./compile.py                    # dynamic build, fetch via apt
    ./compile.py --static           # static (5 MB single-file binary)
    ./compile.py --clean            # wipe ./src/ before building
    ./compile.py --offline DIR      # use .debs already in DIR
    ./compile.py --use-system-libs  # don't bundle, just cc poc.c with system headers/libs

Dependencies the target host must already have: gcc, dpkg-deb,
the kernel uapi headers (linux-libc-dev), and either
  (a) a working apt-get with sources.list pointing somewhere reachable,
  (b) the .deb files staged in --offline DIR, or
  (c) libssl-dev / libkeyutils-dev already installed (--use-system-libs).

Each of the runtime/dev package names below is tried in order; the
first one apt has a candidate for is downloaded.  This handles the
Debian/Ubuntu t64 ABI rename (libssl3 → libssl3t64) transparently.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# (logical-name, [apt-name candidates in priority order]).
# At least one candidate per logical-name must be downloadable, OR
# the user supplies --use-system-libs.
DYNAMIC_PKGS = [
    ("libssl-dev",      ["libssl-dev"]),
    ("libssl-runtime",  ["libssl3t64", "libssl3"]),
    ("libkeyutils-dev", ["libkeyutils-dev"]),
    ("libkeyutils-rt",  ["libkeyutils1"]),
]
STATIC_EXTRA = [
    ("libc6-dev",       ["libc6-dev"]),
]


def run(cmd, **kw):
    if isinstance(cmd, str):
        printable = cmd
    else:
        printable = " ".join(str(c) for c in cmd)
    print(f"  $ {printable}")
    return subprocess.run(cmd, check=True, **kw)


def try_apt_download(pkg, dest):
    """Run `apt-get download pkg` into dest, return True on success."""
    try:
        subprocess.run(["apt-get", "download", pkg],
                       cwd=dest, check=True,
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def fetch_debs(pkg_groups, dest, offline_dir=None):
    """Populate dest with one .deb per logical group.

    For each (logical, [candidate1, candidate2, ...]) try the
    candidates in order; the first hit is taken.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if offline_dir:
        offline_dir = Path(offline_dir).resolve()
        for logical, candidates in pkg_groups:
            for c in candidates:
                matches = sorted(offline_dir.glob(f"{c}_*.deb"))
                if matches:
                    shutil.copy(matches[-1], dest)
                    print(f"  copied {matches[-1].name}  ({logical})")
                    break
            else:
                sys.exit(f"--offline: no .deb for {logical} "
                         f"(tried {candidates}) in {offline_dir}")
        return

    if not shutil.which("apt-get"):
        sys.exit("no apt-get on this host; use --offline DIR or "
                 "--use-system-libs")

    for logical, candidates in pkg_groups:
        for c in candidates:
            print(f"  trying apt-get download {c}  ({logical})")
            if try_apt_download(c, dest):
                print(f"  + got {c}")
                break
        else:
            sys.exit(f"no apt candidate for {logical} "
                     f"(tried {candidates})")


def extract_debs(deb_dir, root):
    root.mkdir(parents=True, exist_ok=True)
    for deb in sorted(deb_dir.glob("*.deb")):
        print(f"  extracting {deb.name}")
        run(["dpkg-deb", "-x", str(deb), str(root)])


def build(here, src_root, static=False, use_system_libs=False):
    """Compile poc.c.  If use_system_libs, skip ./src/ entirely."""
    poc_c = here / "poc.c"
    if not poc_c.is_file():
        sys.exit(f"poc.c not found beside {Path(__file__).name}")
    out = here / "poc"

    cflags = ["-Os", "-s", "-w"]
    ldflags = []

    if not use_system_libs:
        inc = [
            src_root / "usr" / "include",
            src_root / "usr" / "include" / "x86_64-linux-gnu",
        ]
        for d in inc:
            if d.is_dir():
                cflags += ["-I", str(d)]
        libdirs = [
            src_root / "usr" / "lib" / "x86_64-linux-gnu",
            src_root / "lib"  / "x86_64-linux-gnu",
        ]
        for d in libdirs:
            if d.is_dir():
                ldflags += ["-L", str(d)]
                # Help dynamic ld at run time too
                ldflags += [f"-Wl,-rpath,{d}"]

    libs = ["-lkeyutils", "-lcrypto"]
    if static:
        cflags = ["-static"] + cflags
        libs += ["-lpthread", "-ldl"]

    cc = os.environ.get("CC", "cc")
    cmd = [cc] + cflags + ["-o", str(out), str(poc_c)] + ldflags + libs
    run(cmd)
    print(f"\nbuilt {out}  ({out.stat().st_size:,} bytes, "
          f"{'static' if static else 'dynamic'})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--static", action="store_true",
                    help="produce a static binary (single file ~5 MB)")
    ap.add_argument("--clean", action="store_true",
                    help="wipe ./src/ before building")
    ap.add_argument("--offline", metavar="DIR",
                    help="use .debs already in DIR instead of apt-get")
    ap.add_argument("--use-system-libs", action="store_true",
                    help="skip ./src/, just cc against system /usr/include + /usr/lib")
    args = ap.parse_args()

    here = Path(__file__).parent.resolve()
    src = here / "src"

    if args.clean and src.is_dir():
        print(f"== wiping {src}")
        shutil.rmtree(src)

    if args.use_system_libs:
        print(f"== building poc against system libs (no bundling)")
        build(here, None, static=args.static, use_system_libs=True)
        return

    deb_dir  = src / "deb"
    ext_root = src / "extract"

    pkgs = list(DYNAMIC_PKGS)
    if args.static:
        pkgs += STATIC_EXTRA

    if not deb_dir.is_dir() or not list(deb_dir.glob("*.deb")):
        print(f"== fetching {len(pkgs)} package group(s) into {deb_dir}")
        fetch_debs(pkgs, deb_dir, offline_dir=args.offline)

    if not ext_root.is_dir() or not (ext_root / "usr").is_dir():
        print(f"== extracting into {ext_root}")
        extract_debs(deb_dir, ext_root)

    print(f"== building poc")
    build(here, ext_root, static=args.static)
    print("\ndone.  run ./poc as the unprivileged target user.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        sys.exit(f"\n[-] command failed: {e}")
