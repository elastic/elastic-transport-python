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

from elastic_transport import AiohttpHttpNode

pytestmark = pytest.mark.asyncio


class TestAiohttpHttpNode:
    async def _get_mock_node(self, connection_params={}, response_body=b"{}"):
        node = AiohttpHttpNode(**connection_params)
        node._create_aiohttp_session()

        def _dummy_request(*args, **kwargs):
            class DummyResponse:
                async def __aenter__(self, *_, **__):
                    return self

                async def __aexit__(self, *_, **__):
                    pass

                async def read(self):
                    return response_body

            dummy_response = DummyResponse()
            dummy_response.headers = CIMultiDict()
            dummy_response.status = 200
            _dummy_request.call_args = (args, kwargs)
            return dummy_response

        node.session.request = _dummy_request
        return node

    async def test_aiohttp_options(self):
        node = await self._get_mock_node()
        await node.perform_request(
            "GET",
            "/index",
            body=b"hello, world!",
            headers={"key": "value"},
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost/index")
        assert kwargs == {
            "data": b"hello, world!",
            "headers": {"connection": "keep-alive", "key": "value"},
            "timeout": aiohttp.ClientTimeout(
                total=10,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    async def test_aiohttp_options_fingerprint(self):
        node = await self._get_mock_node(
            connection_params={"ssl_assert_fingerprint": ("00:" * 32).strip(":")}
        )
        await node.perform_request(
            "GET",
            "/",
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost/")

        # aiohttp.Fingerprint() doesn't define equality
        fingerprint: aiohttp.Fingerprint = kwargs.pop("ssl")
        assert fingerprint.fingerprint == b"\x00" * 32

        assert kwargs == {
            "data": None,
            "headers": {"connection": "keep-alive"},
            "timeout": aiohttp.ClientTimeout(
                total=10,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    @pytest.mark.parametrize(
        "options",
        [(5, 5, 5), (None, 5, 5), (5, None, 5), (None, None, 0), (5, 5), (None, 10)],
    )
    async def test_aiohttp_options_timeout(self, options):
        if len(options) == 3:
            constructor_timeout, request_timeout, aiohttp_timeout = options
            node = await self._get_mock_node(
                connection_params={"request_timeout": constructor_timeout}
            )
        else:
            request_timeout, aiohttp_timeout = options
            node = await self._get_mock_node()

        await node.perform_request(
            "GET",
            "/",
            request_timeout=request_timeout,
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost/")
        assert kwargs == {
            "data": None,
            "headers": {"connection": "keep-alive"},
            "timeout": aiohttp.ClientTimeout(
                total=aiohttp_timeout,
                connect=None,
                sock_read=None,
                sock_connect=None,
            ),
        }

    async def test_http_compression(self):
        node = await self._get_mock_node(
            {"http_compress": True},
        )

        assert node.http_compress

        # 'content-encoding' shouldn't be set at a session level.
        # Should be applied only if the request is sent with a body.
        assert "content-encoding" not in node.session.headers

        await node.perform_request("GET", "/", body=b"{}")

        args, kwargs = node.session.request.call_args
        assert kwargs["headers"] == {
            "accept-encoding": "gzip",
            "connection": "keep-alive",
            "content-encoding": "gzip",
        }
        assert gzip.decompress(kwargs["data"]) == b"{}"

    @pytest.mark.parametrize("http_compress", [None, False])
    async def test_no_http_compression(self, http_compress):
        node = await self._get_mock_node({"http_compress": http_compress})

        assert node.http_compress is False
        assert "content-encoding" not in node.session.headers

        await node.perform_request("GET", "/", body=b"{}")

        args, kwargs = node.session.request.call_args
        assert kwargs["headers"] == {
            "connection": "keep-alive",
        }
        assert kwargs["data"] == b"{}"

    async def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            await self._get_mock_node(
                {"use_ssl": True, "url_prefix": "url", "verify_certs": False}
            )

        assert 1 == len(w)
        assert (
            "Connecting to 'https://localhost/url' using SSL with verify_certs=False is insecure"
            == str(w[0].message)
        )

    async def test_uses_https_if_verify_certs_is_off_no_show_warning(self):
        with warnings.catch_warnings(record=True) as w:
            node = await self._get_mock_node(
                {
                    "use_ssl": True,
                    "url_prefix": "url",
                    "verify_certs": False,
                    "ssl_show_warn": False,
                }
            )
            await node.perform_request("GET", "/")

        assert w == []

    async def test_merge_headers(self):
        node = await self._get_mock_node(
            connection_params={"headers": {"h1": "v1", "h2": "v2"}}
        )
        resp, _ = await node.perform_request(
            "GET", "/", headers={"H2": "v2p", "H3": "v3"}
        )

        args, kwargs = node.session.request.call_args
        assert args == ("GET", "http://localhost/")
        assert kwargs["headers"] == {
            "connection": "keep-alive",
            "h1": "v1",
            "h2": "v2p",
            "h3": "v3",
        }


async def test_ssl_assert_fingerprint(httpbin_cert_fingerprint):
    with warnings.catch_warnings(record=True) as w:
        node = AiohttpHttpNode(
            host="httpbin.org",
            use_ssl=True,
            port=443,
            ssl_assert_fingerprint=httpbin_cert_fingerprint,
        )
        resp, _ = await node.perform_request("GET", "/")

    assert resp.status == 200
    assert w == []


async def test_default_headers():
    node = AiohttpHttpNode(
        host="httpbin.org",
        use_ssl=True,
        port=443,
    )
    resp, data = await node.perform_request("GET", "/anything")

    assert resp.status == 200
    headers = json.loads(data)["headers"]
    headers.pop("X-Amzn-Trace-Id", None)
    assert headers == {
        "Host": "httpbin.org",
    }


async def test_custom_headers():
    node = AiohttpHttpNode(
        host="httpbin.org",
        use_ssl=True,
        port=443,
        headers={"accept-encoding": "gzip", "Content-Type": "application/json"},
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


def test_repr():
    node = AiohttpHttpNode(host="elasticsearch.com", port=443)
    assert "<AiohttpHttpNode: http://elasticsearch.com:443>" == repr(node)


async def test_head():
    node = AiohttpHttpNode(
        host="httpbin.org",
        use_ssl=True,
        port=443,
        http_compress=True,
    )
    resp, data = await node.perform_request("HEAD", "/anything")

    assert resp.status == 200
    assert resp.headers["content-type"] == "application/json"
    assert data == b""
