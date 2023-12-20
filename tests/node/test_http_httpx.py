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

import pytest
import respx

from elastic_transport import HttpxAsyncHttpNode, NodeConfig
from elastic_transport._node._base import DEFAULT_USER_AGENT


def create_node(node_config: NodeConfig):
    return HttpxAsyncHttpNode(node_config)


class TestHttpxAsyncNodeCreation:
    def test_ssl_context(self):
        ssl_context = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            node = create_node(
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
            _ = create_node(NodeConfig("https", "localhost", 443, verify_certs=False))
        assert (
            str(w[0].message)
            == "Connecting to 'https://localhost:443' using TLS with verify_certs=False is insecure"
        )

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            _ = create_node(
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
            create_node(
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


@pytest.mark.asyncio
class TestHttpxAsyncNode:
    @respx.mock
    async def test_simple_request(self):
        node = create_node(NodeConfig(scheme="http", host="localhost", port=80))
        respx.get("http://localhost/index")
        await node.perform_request(
            "GET", "/index", b"hello world", headers={"key": "value"}
        )
        request = respx.calls.last.request
        assert request.content == b"hello world"
        assert {
            "key": "value",
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }.items() <= request.headers.items()

    @respx.mock
    async def test_compression(self):
        node = create_node(
            NodeConfig(scheme="http", host="localhost", port=80, http_compress=True)
        )
        respx.get("http://localhost/index")
        await node.perform_request("GET", "/index", b"hello world")
        request = respx.calls.last.request
        assert gzip.decompress(request.content) == b"hello world"
        assert {"content-encoding": "gzip"}.items() <= request.headers.items()

    @respx.mock
    async def test_default_timeout(self):
        node = create_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        respx.get("http://localhost/index")
        await node.perform_request("GET", "/index", b"hello world")
        request = respx.calls.last.request
        assert request.extensions["timeout"]["connect"] == 10

    @respx.mock
    async def test_overwritten_timeout(self):
        node = create_node(
            NodeConfig(scheme="http", host="localhost", port=80, request_timeout=10)
        )
        respx.get("http://localhost/index")
        await node.perform_request("GET", "/index", b"hello world", request_timeout=15)
        request = respx.calls.last.request
        assert request.extensions["timeout"]["connect"] == 15

    @respx.mock
    async def test_merge_headers(self):
        node = create_node(
            NodeConfig("http", "localhost", 80, headers={"h1": "v1", "h2": "v2"})
        )
        respx.get("http://localhost/index")
        await node.perform_request(
            "GET", "/index", b"hello world", headers={"h2": "v2p", "h3": "v3"}
        )
        request = respx.calls.last.request
        assert request.headers["h1"] == "v1"
        assert request.headers["h2"] == "v2p"
        assert request.headers["h3"] == "v3"


def test_ssl_assert_fingerprint(httpbin_cert_fingerprint):
    with pytest.raises(ValueError, match="httpx does not support certificate pinning"):
        HttpxAsyncHttpNode(
            NodeConfig(
                scheme="https",
                host="httpbin.org",
                port=443,
                ssl_assert_fingerprint=httpbin_cert_fingerprint,
            )
        )
