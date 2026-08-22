# KrbRelay BOF bridge protocol

The version 3 bridge carries the same complete SPNEGO blobs that KrbRelayUp's
`AcceptSecurityContext_` extracts from the DCE/RPC authentication trailer. It
does not create or accept an operator-supplied Kerberos credential.

The Python service binds to the operator-selected loopback relay port and
accepts only the operator-selected peer. A single `rportfwd_local` exposes that
listener on target loopback. Python opens one proxyable TCP connection to the
operator-selected ADCS address; the unauthenticated HTTP probe, every
`Authorization: Negotiate` leg, and enrollment use that connection.

Each bridge record is a 12-byte header followed by its payload:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII `KRB1` |
| 4 | 1 | Protocol version, currently 3 |
| 5 | 1 | Message type |
| 6 | 2 | Reserved, zero |
| 8 | 4 | Big-endian payload length |
| 12 | n | Payload |

Messages:

| Value | Name | Direction | Payload |
| ---: | --- | --- | --- |
| 3 | `AUTH_TOKEN` | BOF to Python | 1–65535 byte complete SPNEGO blob from RPC |
| 4 | `AUTH_TOKEN` | Python to BOF | 1–65535 byte complete SPNEGO continuation from IIS |
| 5 | `AUTH_OK` | Python to BOF | Empty; terminal BOF success because HTTP is authenticated |
| 6 | `ERROR` | Either | At most 512 bytes of non-sensitive diagnostic UTF-8 text |

By default, authentication material is not encoded into logs, command
arguments, or output. The `--trace-spnego` and `--export-pfx-b64` options
explicitly enable complete token and passwordless PKCS#12 output for a terminal
session where the operator wants to retain those artifacts.

## State mapping to KrbRelayUp

1. The BOF intercepts the first RPC/SPNEGO blob and sends message 3.
2. Python performs the initial unauthenticated IIS probe, sends the blob on its
   persistent connection, extracts IIS's complete `Negotiate` continuation,
   and returns message 4.
3. The BOF supplies that continuation through its hooked
   `AcceptSecurityContext` output. SYSTEM creates the next blob and step 2
   repeats.
4. When IIS responds with 200, Python sends message 5. The BOF restores its
   hook, tears down its COM/RPC objects, joins its in-process worker, and
   returns to Beacon.
5. Python retains the authenticated HTTP connection, generates the machine
   CSR, enrolls through `/certsrv/certfnsh.asp`, retrieves the certificate, and
   independently verifies that it matches the in-memory private key.
