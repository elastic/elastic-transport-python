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

import _ssl  # type: ignore
import hashlib
import socket
import ssl
from binascii import Error as BinasciiError
from binascii import hexlify, unhexlify
from hmac import compare_digest
from typing import Any, List, Optional, Union

from .._exceptions import TlsError
from .._models import NodeConfig
from .._utils import is_ipaddress
from ._base import apply_ssl_context_options

_ENCODING_DER: int = _ssl.ENCODING_DER
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
    """The pinned certificate has to be the only trust anchor."""
    if config.ssl_assert_fingerprint is None:
        return
    normalize_fingerprint(config.ssl_assert_fingerprint)
    if config.verify_certs is False:
        raise ValueError(
            "ssl_assert_fingerprint cannot be combined with verify_certs=False"
        )
    if config.ca_certs:
        raise ValueError("ssl_assert_fingerprint cannot be combined with ca_certs")
    if config.ssl_context is not None:
        raise ValueError("ssl_assert_fingerprint cannot be combined with ssl_context")


def build_pinned_ssl_context(config: NodeConfig) -> ssl.SSLContext:
    """Fetch the cert chain and trust only the certificate that matches."""
    assert config.ssl_assert_fingerprint is not None
    pem = _matching_certificate_pem(config)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    partial = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", None)
    if partial is not None:
        ctx.verify_flags |= partial
    ctx.check_hostname = _check_hostname(config)
    ctx.load_verify_locations(cadata=pem)
    if config.client_cert:
        ctx.load_cert_chain(config.client_cert, config.client_key)
    apply_ssl_context_options(ctx, config)
    return ctx


def apply_assert_hostname(target: Any, config: NodeConfig) -> None:
    hostname = config.ssl_assert_hostname
    if hostname is False or (hostname is None and is_ipaddress(config.host)):
        value: Union[str, bool] = False
    elif isinstance(hostname, str):
        value = hostname
    else:
        return
    if isinstance(target, dict):
        target["assert_hostname"] = value
    else:
        target.assert_hostname = value


def _check_hostname(config: NodeConfig) -> bool:
    if config.ssl_assert_hostname is False:
        return False
    if isinstance(config.ssl_assert_hostname, str):
        return True
    return not is_ipaddress(config.host)


def _matching_certificate_pem(config: NodeConfig) -> str:
    assert config.ssl_assert_fingerprint is not None
    normalized = normalize_fingerprint(config.ssl_assert_fingerprint)
    expected = unhexlify(normalized)
    digestmod = _HASHES_BY_LENGTH[len(normalized)]
    ders = _peer_ders(config)
    seen: List[str] = []
    matched: Optional[bytes] = None
    for der in ders:
        digest = digestmod(der).digest()
        seen.append(hexlify(digest).decode())
        if compare_digest(digest, expected):
            matched = der
    if matched is None:
        presented = '", "'.join(seen)
        raise TlsError(
            f'Fingerprints did not match. Expected "{normalized}", got "{presented}".'
        )
    return ssl.DER_cert_to_PEM_cert(matched)


def _peer_ders(config: NodeConfig) -> List[bytes]:
    # CERT_NONE still requires the peer to prove the leaf private key.
    # Nothing is sent on this socket except the handshake.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_hostname = _sni_hostname(config)
    with socket.create_connection(
        (config.host, config.port), timeout=config.request_timeout
    ) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as ssock:
            sslobj = getattr(ssock, "_sslobj", None)
            get_chain = getattr(sslobj, "get_unverified_chain", None)
            if get_chain is not None:
                ders: List[bytes] = []
                for cert in get_chain():
                    public_bytes = getattr(cert, "public_bytes", None)
                    if public_bytes is not None:
                        ders.append(public_bytes(_ENCODING_DER))
                    elif isinstance(cert, bytes):
                        ders.append(cert)
                if ders:
                    return ders
            leaf = ssock.getpeercert(binary_form=True)
            if isinstance(leaf, bytes):
                return [leaf]
    return []


def _sni_hostname(config: NodeConfig) -> Optional[str]:
    if isinstance(config.ssl_assert_hostname, str):
        return config.ssl_assert_hostname
    if is_ipaddress(config.host):
        return None
    return config.host
