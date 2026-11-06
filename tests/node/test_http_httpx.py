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

import gzip
import ssl
import warnings

import httpx2
import pytest

from elastic_transport import (
    ConnectionError,
    ConnectionTimeout,
    HttpxAsyncHttpNode,
    HttpxHttpNode,
    NodeConfig,
    TlsError,
)
from elastic_transport._node._base import DEFAULT_USER_AGENT


@pytest.fixture
def requests(monkeypatch):
    captured = []

    def handle_request(self, request):
        assert request.method == "GET"
        assert str(request.url) == "http://localhost/index"
        captured.append(request)
        return httpx2.Response(200, content=b"{}")

    async def handle_async_request(self, request):
        return handle_request(self, request)

    monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", handle_request)
    monkeypatch.setattr(
        httpx2.AsyncHTTPTransport, "handle_async_request", handle_async_request
    )
    return captured


def create_sync_node(node_config: NodeConfig):
    return HttpxHttpNode(node_config)


class TestHttpxNodeCreation:
    def test_ssl_context(self):
        ssl_context = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            node = create_sync_node(
                NodeConfig(
                    scheme="https",
                    host="localhost",
                    port=80,
                    ssl_context=ssl_context,
                )
            )
        assert node.client._transport._pool._ssl_context is ssl_context
        assert len(w) == 0

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            _ = create_sync_node(
                NodeConfig("https", "localhost", 443, verify_certs=False)
            )
        assert (
            str(w[0].message)
            == "Connecting to 'https://localhost:443' using TLS with verify_certs=False is insecure"
        )

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            _ = create_sync_node(
                NodeConfig(
                    "https",
                    "localhost",
                    443,
                    verify_certs=False,
                    ssl_show_warn=False,
                )
            )
        assert 0 == len(w)

    def test_ca_certs_with_verify_ssl_false_raises_error(self):
        with pytest.raises(ValueError) as exc:
            create_sync_node(
                NodeConfig(
                    "https",
                    "localhost",
                    443,
                    ca_certs="/ca/certs",
                    verify_certs=False,
                )
            )
            assert (
                str(exc.value) == "You cannot use 'ca_certs' when 'verify_certs=False'"
            )

    def test_path_prefix(self):
        node = create_sync_node(
            NodeConfig(
                "http",
                "localhost",
                9200,
                path_prefix="/test",
            )
        )
        assert node.base_url == "http://localhost:9200/test"
        assert node.client.base_url == "http://localhost:9200/test/"


class TestHttpxNode:
    def test_simple_request(self, requests):
        node = create_sync_node(NodeConfig(scheme="http", host="localhost", port=80))
        node.perform_request("GET", "/index", b"hello world", headers={"key": "value"})
        request = requests[-1]
        assert request.content == b"hello world"
        assert {
            "key": "value",
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }.items() <= request.headers.items()

    def test_compression(self, requests):
        node = create_sync_node(
            NodeConfig(scheme="http", host="localhost", port=80, http_compress=True)
        )
        node.perform_request("GET", "/index", b"hello world")
        request = requests[-1]
        assert gzip.decompress(request.content) == b"hello world"
        assert {"content-encoding": "gzip"}.items() <= request.headers.items()

    def test_default_timeout(self, requests):
        node = create_sync_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        node.perform_request("GET", "/index", b"hello world")
        request = requests[-1]
        assert request.extensions["timeout"]["connect"] == 10

    def test_overwritten_timeout(self, requests):
        node = create_sync_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        node.perform_request("GET", "/index", b"hello world", request_timeout=15)
        request = requests[-1]
        assert request.extensions["timeout"]["connect"] == 15

    def test_merge_headers(self, requests):
        node = create_sync_node(
            NodeConfig("http", "localhost", 80, headers={"h1": "v1", "h2": "v2"})
        )
        node.perform_request(
            "GET", "/index", b"hello world", headers={"h2": "v2p", "h3": "v3"}
        )
        request = requests[-1]
        assert request.headers["h1"] == "v1"
        assert request.headers["h2"] == "v2p"
        assert request.headers["h3"] == "v3"


def create_async_node(node_config: NodeConfig):
    return HttpxAsyncHttpNode(node_config)


class TestHttpxAsyncNodeCreation:
    def test_ssl_context(self):
        ssl_context = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            node = create_async_node(
                NodeConfig(
                    scheme="https",
                    host="localhost",
                    port=80,
                    ssl_context=ssl_context,
                )
            )
        assert node.client._transport._pool._ssl_context is ssl_context
        assert len(w) == 0

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            _ = create_async_node(
                NodeConfig("https", "localhost", 443, verify_certs=False)
            )
        assert (
            str(w[0].message)
            == "Connecting to 'https://localhost:443' using TLS with verify_certs=False is insecure"
        )

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            _ = create_async_node(
                NodeConfig(
                    "https",
                    "localhost",
                    443,
                    verify_certs=False,
                    ssl_show_warn=False,
                )
            )
        assert 0 == len(w)

    def test_ca_certs_with_verify_ssl_false_raises_error(self):
        with pytest.raises(ValueError) as exc:
            create_async_node(
                NodeConfig(
                    "https",
                    "localhost",
                    443,
                    ca_certs="/ca/certs",
                    verify_certs=False,
                )
            )
            assert (
                str(exc.value) == "You cannot use 'ca_certs' when 'verify_certs=False'"
            )

    def test_path_prefix(self):
        node = create_async_node(
            NodeConfig(
                "http",
                "localhost",
                9200,
                path_prefix="/test",
            )
        )
        assert node.base_url == "http://localhost:9200/test"
        assert node.client.base_url == "http://localhost:9200/test/"


@pytest.mark.anyio
class TestHttpxAsyncNode:
    async def test_simple_request(self, requests):
        node = create_async_node(NodeConfig(scheme="http", host="localhost", port=80))
        await node.perform_request(
            "GET", "/index", b"hello world", headers={"key": "value"}
        )
        request = requests[-1]
        assert request.content == b"hello world"
        assert {
            "key": "value",
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }.items() <= request.headers.items()

    async def test_compression(self, requests):
        node = create_async_node(
            NodeConfig(scheme="http", host="localhost", port=80, http_compress=True)
        )
        await node.perform_request("GET", "/index", b"hello world")
        request = requests[-1]
        assert gzip.decompress(request.content) == b"hello world"
        assert {"content-encoding": "gzip"}.items() <= request.headers.items()

    async def test_default_timeout(self, requests):
        node = create_async_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        await node.perform_request("GET", "/index", b"hello world")
        request = requests[-1]
        assert request.extensions["timeout"]["connect"] == 10

    async def test_overwritten_timeout(self, requests):
        node = create_async_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        await node.perform_request("GET", "/index", b"hello world", request_timeout=15)
        request = requests[-1]
        assert request.extensions["timeout"]["connect"] == 15

    async def test_merge_headers(self, requests):
        node = create_async_node(
            NodeConfig("http", "localhost", 80, headers={"h1": "v1", "h2": "v2"})
        )
        await node.perform_request(
            "GET", "/index", b"hello world", headers={"h2": "v2p", "h3": "v3"}
        )
        request = requests[-1]
        assert request.headers["h1"] == "v1"
        assert request.headers["h2"] == "v2p"
        assert request.headers["h3"] == "v3"


@pytest.mark.parametrize("node_class", [HttpxHttpNode, HttpxAsyncHttpNode])
def test_ssl_assert_fingerprint(node_class, cert_fingerprint, httpbin_secure):
    with pytest.raises(ValueError, match="HTTPX2 does not support certificate pinning"):
        node_class(
            NodeConfig(
                scheme="https",
                host=httpbin_secure.host,
                port=httpbin_secure.port,
                ssl_assert_fingerprint=cert_fingerprint,
            )
        )


@pytest.mark.parametrize("node_class", [HttpxHttpNode, HttpxAsyncHttpNode])
@pytest.mark.parametrize(
    "error,expected",
    [
        (httpx2.ReadTimeout("timed out"), ConnectionTimeout),
        (httpx2.ConnectError("connection failed"), ConnectionError),
        (ssl.SSLError("certificate verification failed"), TlsError),
    ],
)
@pytest.mark.anyio
async def test_httpx2_exception_translation(node_class, error, expected, anyio_backend):
    if node_class is HttpxHttpNode and anyio_backend == "trio":
        pytest.skip("sync node only needs to run once")

    node = node_class(NodeConfig("http", "localhost", 9200))

    def fail(request):
        raise error

    async def async_fail(request):
        raise error

    try:
        if node_class is HttpxHttpNode:
            node.client.close()
            node.client = httpx2.Client(transport=httpx2.MockTransport(fail))
            with pytest.raises(expected) as exc:
                node.perform_request("GET", "http://localhost:9200/")
        else:
            await node.client.aclose()
            node.client = httpx2.AsyncClient(transport=httpx2.MockTransport(async_fail))
            with pytest.raises(expected) as exc:
                await node.perform_request("GET", "http://localhost:9200/")
        assert exc.value.errors == (error,)
    finally:
        if node_class is HttpxHttpNode:
            node.close()
        else:
            await node.close()
