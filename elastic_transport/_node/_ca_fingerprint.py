#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

try:
    import _ssl  # type: ignore[import-not-found]
except ImportError:  # pragma: nocover
    _ssl = None

import base64
import hashlib
import socket
import ssl
import urllib.parse
from binascii import Error as BinasciiError
from binascii import hexlify, unhexlify
from hmac import compare_digest
from typing import Any, List, Optional, Union

from .._exceptions import TlsError
from .._models import NodeConfig
from .._utils import is_ipaddress
from ._base import apply_ssl_context_options

_HASHES_BY_LENGTH = {32: hashlib.md5, 40: hashlib.sha1, 64: hashlib.sha256}


def normalize_fingerprint(value: str) -> str:
    fingerprint = value.replace(":", "").lower()
    if len(fingerprint) not in _HASHES_BY_LENGTH:
        valid_lengths = "', '".join(map(str, sorted(_HASHES_BY_LENGTH)))
        raise ValueError(
            f"Fingerprint of invalid length '{len(fingerprint)}'"
            f", should be one of '{valid_lengths}'"
        )
    try:
        unhexlify(fingerprint)
    except BinasciiError:
        raise ValueError(f"Fingerprint is not hexadecimal: {value!r}") from None
    return fingerprint


def validate_fingerprint_options(config: NodeConfig) -> None:
    """Reject a bad fingerprint, or trust settings the pin would ignore."""
    if config.ssl_assert_fingerprint is None:
        return
    normalize_fingerprint(config.ssl_assert_fingerprint)
    if config.verify_certs is False:
        raise ValueError(
            "verify_certs=False cannot be combined with ssl_assert_fingerprint"
        )
    if config.ca_certs is not None:
        raise ValueError("ca_certs cannot be combined with ssl_assert_fingerprint")
    # ponytail: an SSLContext can't be copied without its trust store, so reject it
    if config.ssl_context is not None:
        raise ValueError(
            "ssl_context cannot be combined with ssl_assert_fingerprint. "
            "Use client_cert, client_key and ssl_version instead"
        )


def fetch_pinned_ssl_context(
    config: NodeConfig, timeout: Optional[float], proxy: Optional[str] = None
) -> ssl.SSLContext:
    """Fetch the cert chain and trust only the certificate that matches."""
    assert config.ssl_assert_fingerprint is not None
    pem = _matching_certificate_pem(config, timeout, proxy)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    partial = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", None)
    if partial is not None:
        ctx.verify_flags |= partial
    ctx.check_hostname = _check_hostname(config)
    ctx.load_verify_locations(cadata=pem)
    _apply_caller_tls(ctx, config)
    return ctx


def apply_assert_hostname(target: Any, config: NodeConfig) -> None:
    hostname = config.ssl_assert_hostname
    if hostname is True:
        return
    value: Union[str, bool] = hostname if isinstance(hostname, str) else False
    if isinstance(target, dict):
        target["assert_hostname"] = value
        # Send the same SNI as the probe.
        if isinstance(hostname, str):
            target["server_hostname"] = hostname
    else:
        target.assert_hostname = value


def _check_hostname(config: NodeConfig) -> bool:
    return config.ssl_assert_hostname is True or isinstance(
        config.ssl_assert_hostname, str
    )


def _apply_caller_tls(ctx: ssl.SSLContext, config: NodeConfig) -> None:
    if config.client_cert:
        ctx.load_cert_chain(config.client_cert, config.client_key)
    apply_ssl_context_options(ctx, config)


def _matching_certificate_pem(
    config: NodeConfig, timeout: Optional[float], proxy: Optional[str]
) -> str:
    assert config.ssl_assert_fingerprint is not None
    normalized = normalize_fingerprint(config.ssl_assert_fingerprint)
    expected = unhexlify(normalized)
    digestmod = _HASHES_BY_LENGTH[len(normalized)]
    ders, leaf_only = _peer_ders(config, timeout, proxy)
    seen: List[str] = []
    matched: Optional[bytes] = None
    for der in ders:
        digest = digestmod(der).digest()
        seen.append(hexlify(digest).decode())
        if compare_digest(digest, expected):
            matched = der
    if matched is None:
        presented = '", "'.join(seen)
        message = (
            f'Fingerprints did not match. Expected "{normalized}", got "{presented}".'
        )
        if leaf_only:
            message = f"Only the leaf certificate was available. {message}"
        raise TlsError(message)
    return ssl.DER_cert_to_PEM_cert(matched)


def _probe_context(config: NodeConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _apply_caller_tls(ctx, config)
    # The probe only reads the chain. The pinned context does the verification.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _cert_der(cert: Any) -> Optional[bytes]:
    if isinstance(cert, bytes):
        return cert
    public_bytes = getattr(cert, "public_bytes", None)
    if public_bytes is None or _ssl is None:
        return None
    return public_bytes(_ssl.ENCODING_DER)  # type: ignore[no-any-return]


def _peer_ders(
    config: NodeConfig, timeout: Optional[float], proxy: Optional[str]
) -> tuple[List[bytes], bool]:
    # CERT_NONE still requires the peer to prove the leaf private key.
    # Nothing is sent on this socket except the handshake.
    ctx = _probe_context(config)
    server_hostname = _sni_hostname(config)
    raw = _connect(config.host, config.port, timeout, proxy)
    try:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as ssock:
            get_chain = getattr(ssock, "get_unverified_chain", None)
            if get_chain is None:
                sslobj = getattr(ssock, "_sslobj", None)
                get_chain = getattr(sslobj, "get_unverified_chain", None)
            ders: List[bytes] = []
            if get_chain is not None:
                for cert in get_chain():
                    der = _cert_der(cert)
                    if der is not None:
                        ders.append(der)
            if ders:
                return ders, False
            leaf = ssock.getpeercert(binary_form=True)
            if isinstance(leaf, bytes):
                return [leaf], True
    finally:
        raw.close()
    return [], True


def _connect(
    host: str,
    port: int,
    timeout: Optional[float],
    proxy: Optional[str],
) -> socket.socket:
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)
    parsed = urllib.parse.urlsplit(proxy)
    # ponytail: TLS inside a TLS proxy tunnel needs ssl.MemoryBIO; add it when asked for
    if parsed.scheme == "https":
        raise TlsError("Certificate pinning does not support an https:// proxy")
    if parsed.scheme != "http" or parsed.hostname is None:
        raise TlsError(f"Unsupported proxy URL for certificate pinning: {proxy!r}")
    sock = socket.create_connection(
        (parsed.hostname, parsed.port or 80), timeout=timeout
    )
    try:
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if parsed.username is not None:
            user = urllib.parse.unquote(parsed.username)
            password = urllib.parse.unquote(parsed.password or "")
            token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        status = _proxy_status(sock)
        if status != 200:
            raise TlsError(f"Proxy CONNECT failed: {status}")
        return sock
    except Exception:
        sock.close()
        raise


def _proxy_status(sock: socket.socket) -> int:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    line = buf.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = line.split(" ")
    if len(parts) < 2 or not parts[1].isdigit():
        raise TlsError(f"Proxy CONNECT failed: {line!r}")
    return int(parts[1])


def _sni_hostname(config: NodeConfig) -> Optional[str]:
    if isinstance(config.ssl_assert_hostname, str):
        return config.ssl_assert_hostname
    if is_ipaddress(config.host):
        return None
    return config.host
