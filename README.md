# SSH Transport Handshake, Built from the Specification

A working Java client/server pair that performs the **sequence** of the SSH
transport-layer handshake from first principles: identification exchange,
Diffie-Hellman key agreement, server authentication by digital signature, and
session-key derivation — using the JDK's cryptographic primitives directly rather
than an SSH library.

## Scope — read this first

This is **not** wire-compatible with RFC 4253 and will not interoperate with
OpenSSH. Messages are exchanged as Java-serialized objects, not as SSH binary
packets, and several parts of the real protocol are deliberately absent (listed
below). The goal was to understand how key exchange, server authentication and
key derivation fit together by building them, not to produce a drop-in SSH.

A partial implementation described honestly is more useful than one that
overstates what it does — so the gaps are documented as carefully as the
features.

---

## The handshake

```
   CLIENT                                           SERVER
     │                                                │
     │                            ┌───────────────────┴───────────────┐
     │                            │ on startup:                       │
     │                            │  • RSA-2048 keypair (host key)    │
     │                            │  • DH-2048 domain parameters      │
     │                            └───────────────────┬───────────────┘
     │                                                │
     │ ◄──── 1. identification + algorithm lists ──── │   server_id, kex,
     │                                                │   hostkey, cipher, mac
     │                                                │
     │ ◄──── 2. server DH public key ──────────────── │
     │ ───── 2. client DH public key ───────────────► │
     │                                                │
     │      ══ both derive the same shared secret ══  │
     │                                                │
     │ ◄──── 3. RSA public key + signature ────────── │   SHA256withRSA
     │        verify signature over shared secret     │   over shared secret
     │                                                │
     │      ══ both derive a 32-byte session key ══   │   SHA-256 expand loop
     │                                                │
     │ ◄──── 4. "Session keys established" ────────── │
     │                                                │
```

## What is implemented

| Step | Detail |
|---|---|
| Transport | TCP on port `22226`; the server is threaded, one thread per client |
| Identification | Server sends an ID string plus its supported algorithm lists (kex, hostkey, encryption, mac) |
| Key exchange | Diffie-Hellman, 2048-bit domain parameters generated at server startup, via JCE `KeyAgreement` |
| Server authentication | RSA-2048 host key; `SHA256withRSA` signature over the shared secret, verified by the client |
| Session keys | 32 bytes derived from the shared secret through a SHA-256 expand loop |
| Client modes | **Direct** (minimal output) and **Interactive** (prints every step, Base64 of each key) |

The interactive mode is the point of the project: it shows the DH public keys,
the shared secret, the server's RSA key, the PRK and the derived session key as
they are produced, so the handshake can be watched rather than assumed.

## Running it

Two source files, no dependencies beyond the JDK, and therefore no build tool.
Compiles and runs on Java 17:

```bash
javac -d out src/main/java/Project/SSHServer.java src/main/java/Project/SSHClient.java
```

```bash
java -cp out Project.SSHServer
```

Then in a second terminal:

```bash
java -cp out Project.SSHClient
```

Choose `1` for direct mode or `2` to step through the handshake.

Verified output of a successful run:

```
# server
Server starting up...
Awaiting client connections...
Client connected! Initiating handshake...
Handshake successfull. Procceding to establish secure channel...

# client
Starting handshake protocol...
Server identity verified. Handshake successful.
Secure channel established. You can now begin your session.
```

### Interactive mode

![run1](https://github.com/user-attachments/assets/98d092e8-9349-498c-93e5-ad687b143d07)

![run3](https://github.com/user-attachments/assets/14b57d09-1b3a-4c85-8f65-b6c32e07b36c)

![run5](https://github.com/user-attachments/assets/ed0591a7-f274-4eb0-8c04-220167aaa3fd)

---

## How this differs from real SSH

The interesting part of building this was discovering what the real protocol does
that a straightforward implementation does not. Each of these is a genuine gap,
not a simplification of detail.

**1. There is no exchange hash, so the negotiation is unprotected.**
Real SSH computes an exchange hash `H` over both identification strings, both
KEXINIT payloads, the host key, both DH public keys and the shared secret — and
signs *that*. Here the server signs the raw shared secret alone. The consequence
is concrete: an attacker who tampered with the advertised algorithm lists would
not be detected, because nothing in the signature covers them. The exchange hash
is what makes SSH's negotiation tamper-evident retroactively, and leaving it out
is what makes that mechanism visible.

**2. Algorithms are advertised, not negotiated.**
The server sends its lists and the client prints them. The client never sends its
own list, and no selection is made or agreed — there is no `SSH_MSG_KEXINIT`
round. The advertised `aes256-ctr` and `hmac-sha256` are never actually used.

**3. The session key is derived and then discarded.**
Both sides compute the same 32-byte key, and neither encrypts anything with it.
After the handshake the socket is closed; the "secure channel" message is a
statement, not a fact. Real SSH would transition with `SSH_MSG_NEWKEYS` and every
subsequent byte would be encrypted and MACed.

**4. The derivation is HKDF-shaped, but it is not HKDF.**
RFC 5869 HKDF extracts with `HMAC(salt, IKM)` and expands with HMAC. This code
uses a plain `SHA-256(shared_secret)` as the PRK and plain SHA-256 in the expand
loop, with no HMAC anywhere. It produces deterministic, matching output on both
sides, which is why it works — but it does not have HKDF's security argument, and
calling it HKDF would be wrong. Real SSH also derives **six** distinct keys (two
IVs, two encryption keys, two MAC keys) from the one secret; this derives one.

**5. The host key is trusted on sight.**
The client verifies that the signature matches the public key the server just
sent — which proves the peer holds the corresponding private key, and stops a
passive attacker. It does nothing against an active man-in-the-middle, who simply
presents their own keypair. Real SSH closes this with `known_hosts`: the
host key must match one pinned on first contact. Without that check, the
signature verifies a claim the attacker is free to make.

**6. No user authentication and no channels.**
RFC 4252 (user auth) and RFC 4254 (channels, shell, exec, port forwarding) are
entirely out of scope. The `ssh>` prompt in interactive mode echoes commands back
and is explicitly labelled simulated — nothing is executed anywhere.

Also absent: rekeying after the initial exchange, compression, and the binary
packet protocol itself.

## What building it taught me

- **Signing the secret is not the same as signing the conversation.** The
  difference between "the peer knows the DH secret" and "the peer agrees with me
  about everything that was said" is exactly the exchange hash, and it is not
  obvious until you try to write down what the signature actually guarantees.
- **Authentication without pinning proves less than it looks like it does.** A
  valid signature over a key the attacker supplied is a valid signature. The
  trust has to be anchored somewhere outside the handshake.
- **Diffie-Hellman gives you a shared secret, not a usable key.** The secret is a
  large integer with structure; turning it into key material is a separate step
  with its own requirements, which is why the KDF exists at all rather than
  hashing once and moving on.

---

## Security notice

**This is a learning implementation. Do not use it to protect real traffic.**
It has not been audited, it implements a fraction of the protocol, it does not
encrypt anything after the handshake, and the host key is accepted without
verification. It is intended to be read, not deployed.

## Repository layout

```
src/main/java/Project/
├── SSHServer.java    host keys, DH parameters, threaded accept loop,
│                     identification, key exchange, signing, key derivation
└── SSHClient.java    direct and interactive modes, DH exchange,
                      signature verification, key derivation
```

## Known issues

- Interactive mode calls `scanner.nextLine()` twice in a row to work around
  mixing `nextInt()` with line reads — it works, but it is a workaround.
- A TCP connection that opens and closes without speaking the protocol makes the
  server log `Error handling client` rather than being ignored as a probe.
- The repository name is misspelled (`Handsahke`).
- The internal class is named `ClinetHandler`.
