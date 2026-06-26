# pedit-cow (CVE-2026-46331)

Reproduction harness for **pedit COW** — a `net/sched` `act_pedit` partial
copy-on-write page-cache write in the Linux kernel, turned into unprivileged
local root. The exploit and primitive are by
[sgkdev](https://github.com/sgkdev/packet_edit_meme); this directory vendors
that PoC verbatim plus a co-located `env.yaml` for our test harness.

> [!WARNING]
> Authorized testing only. Do not run this against systems you do not own or
> have explicit written permission to test.

## What it is

`tcf_pedit_act()` validates the writable copy-on-write range once, before the
per-key offsets are resolved. A first NETWORK pedit key inflates the IP IHL so a
later TCP key resolves past that stale range — into the page-cache page that
`sendfile()` placed in the egress skb. The exploit overwrites the cached ELF
entry of setuid-root `/bin/su` with `setgid(0)+setuid(0)+execve("/bin/sh")`
shellcode; invoking `su` then yields root from the poisoned cached page.

Bug span: v5.18 (culprit `899ee91156e5`) up to the fix in v7.1-rc7. CAP_NET_ADMIN
for the primitive is obtained unprivileged via `unshare(CLONE_NEWUSER|CLONE_NEWNET)`.

## Files

| File | Description |
| --- | --- |
| `packet_edit_meme.c` | sgkdev's unprivileged-user to root exploit (vendored). |
| `pedit_primitive.c` / `.h` | the page-cache overwrite primitive (vendored). |
| `env.yaml` | environment manifest: target kernel, modules, build, run, expect. |

## Reproduce

```bash
# On a disposable VM in the vulnerable window (v5.18 .. v7.1-rc6):
gcc -O2 -w -o peditcow packet_edit_meme.c pedit_primitive.c

# Run as an unprivileged user; on success su's cached entry runs the shellcode:
echo id | timeout 25 ./peditcow        # -> uid=0(root) ...
```

Roots `/usr/bin/su` on the pinned vulnerable kernel. See `env.yaml` for the full
manifest, including the patched-kernel negative control (`v7.1-rc7`). On
AppArmor-restricted Ubuntu, pass `--ubuntu` to transition through a
userns-permitting profile first.

## Detection

The principle that runs through this whole page-cache-write family: you don't
catch a kernel LPE by chasing the root shell at the end of it — you catch the
one abnormal operation the exploit cannot avoid performing. Where that operation
sits on the *rarity* scale decides the strategy.

CopyFail and DirtyFrag ride operations that legitimate software performs
constantly (`setsockopt()` — AF_ALG keying, IPsec/AFS setup), so a single call
means nothing and the detection has to recognize the exploit's *pattern* rather
than any one event — the approach we walked through in our "thinking outside the
box" write-ups.

PEdit-CoW sits at the other end of that scale: the operation its primitive
depends on is itself privileged and uncommon, which is exactly the kind of thing
an eBPF sensor can key on cleanly. We run a working detection for it (same family
as DirtyCBC and DirtyClone); the specifics are kept private.

Further reading on detecting this exploit family by thinking outside the box:

- [Detecting CopyFail & DirtyFrag](https://medium.com/@miggo-engineering/detecting-copyfail-dirtyfrag-by-thinking-outside-the-box-3cae021ca94c)
- [Detecting the nftables catchall UAF (CVE-2026-23111)](https://medium.com/@miggo-engineering/detecting-the-nftables-catchall-use-after-free-cve-2026-23111-by-thinking-outside-the-box-2227654d5acf)

## Credits

Exploit and page-cache-write primitive:
[sgkdev/packet_edit_meme](https://github.com/sgkdev/packet_edit_meme). The
underlying `act_pedit` bug was fixed upstream (mainline `v7.1-rc7`). This
directory vendors sgkdev's PoC for research and detection purposes only.
