# Research - Rafael David Tinoco (Miggo Security)

```text
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

╔════════════════════════════════════════════════════════════╗
║           ::  KERNEL  .  eBPF  .  INTERNALS  ::            ║
║                                                            ║
║            "the system is only as secure as the            ║
║           assumptions nobody bothered to check"            ║
║                                                            ║
║      .oO  exploits + detections for the curious  Oo.       ║
╚════════════════════════════════════════════════════════════╝
 -=[ a personal textfile in the spirit of the old boards ]=-
   -=[ knowledge wants to be understood, not just used ]=-
 ____________________________________________________________
/   greetz: every maintainer who reads a bug report twice    \
\____________________________________________________________/
```

A collection of security research focused on the Linux kernel and other
critical subsystems — eBPF, kernel internals, operating-system libraries,
and the low-level machinery that modern systems are built on.

This repository documents both **offensive** and **defensive** angles: how
certain classes of vulnerabilities arise and can be exploited, and how the
same behavior can be observed, detected, and mitigated.

## ⚠️ Disclaimer

**This repository exists for educational and research purposes only.**

Everything published here is the result of independent security research and
is shared in the spirit of advancing collective understanding of how these
systems work and how they fail. Some of the material describes exploitation
techniques, proof-of-concept code, and other content that **should be handled
with care**.

By accessing, cloning, or using anything in this repository, you acknowledge
and agree to the following:

- **Education first.** All content is provided solely for learning, teaching,
  defensive research, and the improvement of system security. It is not a
  toolkit for attacking systems you do not own.

- **Authorized use only.** You are responsible for ensuring that any use of
  this material is lawful in your jurisdiction and that you have **explicit
  authorization** for any system you test against. Unauthorized access to
  computer systems is illegal in most parts of the world.

- **Use with care.** Proof-of-concept code, exploits, and low-level techniques
  can crash systems, corrupt data, or cause unintended damage. Run them only in
  isolated, disposable environments (VMs, containers, dedicated lab machines) —
  never on production systems or systems you cannot afford to lose.

- **No warranty.** This material is provided "as is", without warranty of any
  kind, express or implied. It may be incomplete, outdated, or incorrect.

- **No liability.** The author(s) accept no responsibility or liability for any
  damage, loss, or legal consequence resulting from the use or misuse of any
  information or code contained in this repository.

- **Personal repository.** This is the author's personal repository. All views,
  opinions, and content are the author's own and do not represent the positions
  of any current or former employer.

If you do not agree with these terms, **do not use this repository.**

## Employer disclaimer

The author conducts security research professionally at **Miggo Security**.
However, **this repository is a personal project and is not owned, endorsed,
sponsored, or reviewed by Miggo Security.** Nothing here should be interpreted
as a statement, product, or position of Miggo Security, nor as evidence of any
specific engagement, client, or internal work.

Miggo Security bears **no responsibility or liability** for any content in this
repository or for any use or misuse of it. Any material published here that
overlaps with the author's professional work is shared only after the author
has obtained the necessary clearance to make it public; the presence of such
material implies nothing about ongoing or confidential activities.

## Responsible disclosure

Where this research touches real, unpatched vulnerabilities, it follows
responsible-disclosure practices: affected vendors and maintainers are notified
and given reasonable time to remediate before technical details are published.
