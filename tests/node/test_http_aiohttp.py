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
import json
import warnings

import aiohttp
import pytest
from multidict import CIMultiDict

from elastic_transport import AiohttpHttpNode, NodeConfig
from elastic_transport._node._base import DEFAULT_USER_AGENT


class TestAiohttpHttpNode:
    @pytest.mark.asyncio
    async def _get_mock_node(self, node_config, response_body=b"{}"):
        node = AiohttpHttpNode(node_config)
        node._create_aiohttp_session()

        def _dummy_request(*args, **kwargs):
            class DummyResponse:
                async def __aenter__(self, *_, **__):
                    return self

                async def __aexit__(self, *_, **__):
                    pass

                async def read(self):
                    return response_body if args[0] != "HEAD" else b""

                async def release(self):
                    return None

            dummy_response = DummyResponse()
            dummy_response.headers = CIMultiDict()
            dummy_response.status = 200
            _dummy_request.call_args = (args, kwargs)
            return dummy_response

        node.session.request = _dummy_request
        return node

    @pytest.mark.asyncio
    async def test_aiohttp_options(self):
        node = await self._get_mock_node(
            NodeConfig(scheme="http", host="localhost", port=80)
        )
        await node.perform_request(
            "GET",
            "/index",
            body=b"hello, world!",
            headers={"key": "value"},
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost:80/index")
        assert kwargs == {
            "data": b"hello, world!",
            "headers": {
                "connection": "keep-alive",
                "key": "value",
                "user-agent": DEFAULT_USER_AGENT,
            },
            "timeout": aiohttp.ClientTimeout(
                total=10,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    @pytest.mark.asyncio
    async def test_aiohttp_options_fingerprint(self):
        node = await self._get_mock_node(
            NodeConfig(
                scheme="https",
                host="localhost",
                port=443,
                ssl_assert_fingerprint=("00:" * 32).strip(":"),
            )
        )
        await node.perform_request(
            "GET",
            "/",
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "https://localhost:443/")

        # aiohttp.Fingerprint() doesn't define equality
        fingerprint: aiohttp.Fingerprint = kwargs.pop("ssl")
        assert fingerprint.fingerprint == b"\x00" * 32

        assert kwargs == {
            "data": None,
            "headers": {"connection": "keep-alive", "user-agent": DEFAULT_USER_AGENT},
            "timeout": aiohttp.ClientTimeout(
                total=10,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    @pytest.mark.parametrize(
        "options",
        [(5, 5, 5), (None, 5, 5), (5, None, 0), (None, None, 0), (5, 5), (None, 0)],
    )
    @pytest.mark.asyncio
    async def test_aiohttp_options_timeout(self, options):
        if len(options) == 3:
            constructor_timeout, request_timeout, aiohttp_timeout = options
            node = await self._get_mock_node(
                NodeConfig(
                    scheme="http",
                    host="localhost",
                    port=80,
                    request_timeout=constructor_timeout,
                )
            )
        else:
            request_timeout, aiohttp_timeout = options
            node = await self._get_mock_node(
                NodeConfig(scheme="http", host="localhost", port=80)
            )

        await node.perform_request(
            "GET",
            "/",
            request_timeout=request_timeout,
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost:80/")
        assert kwargs == {
            "data": None,
            "headers": {"connection": "keep-alive", "user-agent": DEFAULT_USER_AGENT},
            "timeout": aiohttp.ClientTimeout(
                total=aiohttp_timeout,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    @pytest.mark.asyncio
    async def test_http_compression(self):
        node = await self._get_mock_node(
            NodeConfig(scheme="http", host="localhost", port=80, http_compress=True)
        )

        # 'content-encoding' shouldn't be set at a session level.
        # Should be applied only if the request is sent with a body.
        assert "content-encoding" not in node.session.headers

        await node.perform_request("GET", "/", body=b"{}")

        args, kwargs = node.session.request.call_args
        assert kwargs["headers"] == {
            "accept-encoding": "gzip",
            "connection": "keep-alive",
            "content-encoding": "gzip",
            "user-agent": DEFAULT_USER_AGENT,
        }
        assert gzip.decompress(kwargs["data"]) == b"{}"

    @pytest.mark.parametrize("http_compress", [None, False])
    @pytest.mark.asyncio
    async def test_no_http_compression(self, http_compress):
        node = await self._get_mock_node(
            NodeConfig(
                scheme="http", host="localhost", port=80, http_compress=http_compress
            )
        )

        assert "content-encoding" not in node.session.headers

        await node.perform_request("GET", "/", body=b"{}")

        args, kwargs = node.session.request.call_args
        assert kwargs["headers"] == {
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }
        assert kwargs["data"] == b"{}"

    @pytest.mark.parametrize("path_prefix", ["url", "/url"])
    @pytest.mark.asyncio
    async def test_uses_https_if_verify_certs_is_off(self, path_prefix):
        with warnings.catch_warnings(record=True) as w:
            await self._get_mock_node(
                NodeConfig(
                    scheme="https",
                    host="localhost",
                    port=443,
                    path_prefix=path_prefix,
                    verify_certs=False,
                )
            )

        assert 1 == len(w)
        assert (
            "Connecting to 'https://localhost:443/url' using TLS with verify_certs=False is insecure"
            == str(w[0].message)
        )

    @pytest.mark.asyncio
    async def test_uses_https_if_verify_certs_is_off_no_show_warning(self):
        with warnings.catch_warnings(record=True) as w:
            node = await self._get_mock_node(
                NodeConfig(
                    scheme="https",
                    host="localhost",
                    port=443,
                    path_prefix="url",
                    ssl_show_warn=False,
                )
            )
            await node.perform_request("GET", "/")

        assert w == []

    @pytest.mark.asyncio
    async def test_merge_headers(self):
        node = await self._get_mock_node(
            NodeConfig(
                scheme="https",
                host="localhost",
                port=443,
                headers={"h1": "v1", "h2": "v2"},
            )
        )
        resp, _ = await node.perform_request(
            "GET", "/", headers={"H2": "v2p", "H3": "v3"}
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "https://localhost:443/")
        assert kwargs["headers"] == {
            "connection": "keep-alive",
            "h1": "v1",
            "h2": "v2p",
            "h3": "v3",
            "user-agent": DEFAULT_USER_AGENT,
        }

    @pytest.mark.parametrize("aiohttp_fixed_head_bug", [True, False])
    @pytest.mark.asyncio
    async def test_head_workaround(self, aiohttp_fixed_head_bug):
        from elastic_transport._node import _http_aiohttp

        prev = _http_aiohttp._AIOHTTP_FIXED_HEAD_BUG
        try:
            _http_aiohttp._AIOHTTP_FIXED_HEAD_BUG = aiohttp_fixed_head_bug

            node = await self._get_mock_node(
                NodeConfig(
                    scheme="https",
                    host="localhost",
                    port=443,
                )
            )
            resp, data = await node.perform_request("HEAD", "/anything")

            method, url = node.session.request.call_args[0]
            assert method == "HEAD" if aiohttp_fixed_head_bug else "GET"
            assert url == "https://localhost:443/anything"

            assert resp.status == 200
            assert data == b""

        finally:
            _http_aiohttp._AIOHTTP_FIXED_HEAD_BUG = prev


@pytest.mark.asyncio
async def test_ssl_assert_fingerprint(httpbin_cert_fingerprint):
    with warnings.catch_warnings(record=True) as w:
        node = AiohttpHttpNode(
            NodeConfig(
                scheme="https",
                host="httpbin.org",
                port=443,
                ssl_assert_fingerprint=httpbin_cert_fingerprint,
            )
        )
        resp, _ = await node.perform_request("GET", "/")

    assert resp.status == 200
    assert [str(x.message) for x in w if x.category != DeprecationWarning] == []


@pytest.mark.asyncio
async def test_default_headers():
    node = AiohttpHttpNode(NodeConfig(scheme="https", host="httpbin.org", port=443))
    resp, data = await node.perform_request("GET", "/anything")

    assert resp.status == 200
    headers = json.loads(data)["headers"]
    headers.pop("X-Amzn-Trace-Id", None)
    assert headers == {"Host": "httpbin.org", "User-Agent": DEFAULT_USER_AGENT}


@pytest.mark.asyncio
async def test_custom_headers():
    node = AiohttpHttpNode(
        NodeConfig(
            scheme="https",
            host="httpbin.org",
            port=443,
            headers={"accept-encoding": "gzip", "Content-Type": "application/json"},
        )
    )
    resp, data = await node.perform_request(
        "GET",
        "/anything",
        headers={
            "conTent-type": "application/x-ndjson",
            "user-agent": "custom-agent/1.2.3",
        },
    )

    assert resp.status == 200
    headers = json.loads(data)["headers"]
    headers.pop("X-Amzn-Trace-Id", None)
    assert headers == {
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-ndjson",
        "Host": "httpbin.org",
        "User-Agent": "custom-agent/1.2.3",
    }


@pytest.mark.asyncio
async def test_custom_user_agent():
    node = AiohttpHttpNode(
        NodeConfig(
            scheme="https",
            host="httpbin.org",
            port=443,
            headers={
                "accept-encoding": "gzip",
                "Content-Type": "application/json",
                "user-agent": "custom-agent/1.2.3",
            },
        )
    )
    resp, data = await node.perform_request(
        "GET",
        "/anything",
    )

    assert resp.status == 200
    headers = json.loads(data)["headers"]
    headers.pop("X-Amzn-Trace-Id", None)
    assert headers == {
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json",
        "Host": "httpbin.org",
        "User-Agent": "custom-agent/1.2.3",
    }


def test_repr():
    node = AiohttpHttpNode(NodeConfig(scheme="https", host="localhost", port=443))
    assert "<AiohttpHttpNode(https://localhost:443)>" == repr(node)


@pytest.mark.asyncio
async def test_head():
    node = AiohttpHttpNode(
        NodeConfig(scheme="https", host="httpbin.org", port=443, http_compress=True)
    )
    resp, data = await node.perform_request("HEAD", "/anything")

    assert resp.status == 200
    assert resp.headers["content-type"] == "application/json"
    assert data == b""
