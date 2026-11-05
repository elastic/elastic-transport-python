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

import hashlib
import http.server
import ssl
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Tuple, Type

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from elastic_transport import NodeConfig, RequestsHttpNode, TlsError, Urllib3HttpNode
from elastic_transport._node._base import BaseNode


def _material() -> Tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
    now = datetime.now(timezone.utc)
    ca_key = _key()
    ca_name = _cn("Test Dev CA")
    ca_cert = _cert(
        ca_name,
        ca_name,
        ca_key,
        ca_key,
        now - timedelta(days=1),
        now + timedelta(days=2),
        ca=True,
    )
    good_key = _key()
    forged_key = _key()
    expired_key = _key()
    other_key = _key()
    return (
        _pem_cert(ca_cert),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                good_key,
                ca_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="localhost",
            )
        ),
        _pem_key(good_key),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                forged_key,
                forged_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="localhost",
            )
        ),
        _pem_key(forged_key),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                expired_key,
                ca_key,
                now - timedelta(days=10),
                now - timedelta(days=1),
                san="localhost",
            )
        ),
        _pem_key(expired_key),
        _pem_cert(
            _cert(
                _cn("other.example"),
                ca_name,
                other_key,
                ca_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="other.example",
            )
        ),
        _pem_key(other_key),
    )


def _key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cn(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _cert(
    subject: x509.Name,
    issuer: x509.Name,
    key: RSAPrivateKey,
    signer: RSAPrivateKey,
    start: datetime,
    end: datetime,
    ca: bool = False,
    san: str = "",
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(True, None), critical=True
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(signer, hashes.SHA256())


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


CA_PEM, GOOD, GOOD_KEY, FORGED, FORGED_KEY, EXPIRED, EXPIRED_KEY, OTHER, OTHER_KEY = (
    _material()
)
FINGERPRINT = hashlib.sha256(ssl.PEM_cert_to_DER_cert(CA_PEM.decode())).hexdigest()
LEAF_FINGERPRINT = hashlib.sha256(ssl.PEM_cert_to_DER_cert(GOOD.decode())).hexdigest()
COLON_FINGERPRINT = ":".join(
    FINGERPRINT[i : i + 2] for i in range(0, len(FINGERPRINT), 2)
).upper()

NODES = [Urllib3HttpNode, RequestsHttpNode]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: "_Server" = self.server  # type: ignore[assignment]
        server.hits += 1
        auth = self.headers.get("Authorization")
        if auth is not None:
            server.auths.append(auth)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _Server(http.server.HTTPServer):
    hits: int
    auths: list

    def __init__(self, address: Tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, _Handler)
        self.hits = 0
        self.auths = []
        self.socket = context.wrap_socket(self.socket, server_side=True)


@contextmanager
def serve(leaf: bytes, key: bytes) -> Iterator[_Server]:
    with tempfile.TemporaryDirectory() as tmp:
        chain = Path(tmp) / "chain.pem"
        key_path = Path(tmp) / "key.pem"
        chain.write_bytes(leaf + b"\n" + CA_PEM)
        key_path.write_bytes(key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(chain), keyfile=str(key_path))
        server = _Server(("127.0.0.1", 0), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()


def _port(server: _Server) -> int:
    port = server.server_address[1]
    assert isinstance(port, int)
    return port


def _pinned_context(node: BaseNode) -> ssl.SSLContext:
    if isinstance(node, Urllib3HttpNode):
        assert node.pool is not None
        context = node.pool.conn_kw["ssl_context"]
        assert node.pool.ca_certs is None
    else:
        context = node._adapter._pinned_context  # type: ignore[attr-defined]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) == 1
    return context


@pytest.mark.parametrize("node_cls", NODES)
def test_constructor_does_not_connect(node_cls: Type[BaseNode]) -> None:
    node = node_cls(
        NodeConfig(
            "https",
            "127.0.0.1",
            1,
            ssl_assert_fingerprint="ab" * 32,
        )
    )
    if isinstance(node, Urllib3HttpNode):
        assert node.pool is None
    node.close()


@pytest.mark.parametrize("node_cls", NODES)
@pytest.mark.parametrize("fingerprint", ["", "../", "?#", "/etc/passwd", "FO:OB:AR"])
def test_bad_fingerprint_sends_no_http(
    node_cls: Type[BaseNode], fingerprint: str
) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        with pytest.raises(ValueError):
            node_cls(
                NodeConfig(
                    "https",
                    "localhost",
                    _port(server),
                    ssl_assert_fingerprint=fingerprint,
                )
            )
        assert server.hits == 0


@pytest.mark.parametrize("node_cls", NODES)
def test_rejects_other_trust_settings(node_cls: Type[BaseNode]) -> None:
    with pytest.raises(ValueError, match="verify_certs=False"):
        node_cls(
            NodeConfig(
                "https",
                "localhost",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                verify_certs=False,
            )
        )
    with pytest.raises(ValueError, match="ca_certs"):
        node_cls(
            NodeConfig(
                "https",
                "localhost",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                ca_certs="../",
            )
        )
    with pytest.raises(ValueError, match="ssl_context"):
        node_cls(
            NodeConfig(
                "https",
                "localhost",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            )
        )


@pytest.mark.parametrize("node_cls", NODES)
def test_pin_sends_one_request(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=COLON_FINGERPRINT,
                headers={"authorization": "ApiKey secret"},
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert server.auths == ["ApiKey secret"]
            context = _pinned_context(node)
            assert context.check_hostname is True
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.hits == 2
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_leaf_fingerprint_is_a_trust_anchor(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=LEAF_FINGERPRINT,
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            # get_ca_certs skips non-CA trust anchors, so a leaf pin stays an empty list
            context = (
                node.pool.conn_kw["ssl_context"]
                if isinstance(node, Urllib3HttpNode)
                else node._adapter._pinned_context  # type: ignore[attr-defined]
            )
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.get_ca_certs() == []
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_forged_leaf_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(FORGED, FORGED_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                headers={"authorization": "ApiKey secret"},
            )
        )
        try:
            with pytest.raises(TlsError, match="signature|certificate|verify") as exc:
                node.perform_request("GET", "/")
            assert "Fingerprints did not match" not in str(exc.value)
            assert server.hits == 0
            assert server.auths == []
            _pinned_context(node)
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_expired_certificate_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(EXPIRED, EXPIRED_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
            )
        )
        try:
            with pytest.raises(TlsError, match="expired"):
                node.perform_request("GET", "/")
            assert server.hits == 0
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_hostname_mismatch_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(OTHER, OTHER_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
            )
        )
        try:
            with pytest.raises(TlsError, match="Hostname mismatch") as exc:
                node.perform_request("GET", "/")
            assert "Fingerprints did not match" not in str(exc.value)
            assert server.hits == 0
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_hostname_opt_out(node_cls: Type[BaseNode]) -> None:
    with serve(OTHER, OTHER_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname=False,
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert _pinned_context(node).check_hostname is False
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_wrong_fingerprint_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint="0" * 64,
            )
        )
        try:
            with pytest.raises(TlsError, match="Fingerprints did not match") as exc:
                node.perform_request("GET", "/")
            assert "0" * 64 in str(exc.value)
            assert server.hits == 0
        finally:
            node.close()


def test_invalid_length_message() -> None:
    with pytest.raises(ValueError) as exc:
        Urllib3HttpNode(
            NodeConfig("https", "localhost", 1, ssl_assert_fingerprint="0000")
        )
    assert (
        str(exc.value)
        == "Fingerprint of invalid length '4', should be one of '32', '40', '64'"
    )
