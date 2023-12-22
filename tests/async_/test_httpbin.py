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

import dataclasses
import json

import pytest

from elastic_transport import AiohttpHttpNode, AsyncTransport
from elastic_transport._node._base import DEFAULT_USER_AGENT

from ..test_httpbin import parse_httpbin


@pytest.mark.asyncio
async def test_simple_request(httpbin_node_config):
    t = AsyncTransport([httpbin_node_config])

    resp, data = await t.perform_request(
        "GET",
        "/anything?key[]=1&key[]=2&q1&q2=",
        headers={"Custom": "headeR", "content-type": "application/json"},
        body={"JSON": "body"},
    )
    assert resp.status == 200
    assert data["method"] == "GET"
    assert data["url"] == "https://httpbin.org/anything?key[]=1&key[]=2&q1&q2="

    # httpbin makes no-value query params into ''
    assert data["args"] == {
        "key[]": ["1", "2"],
        "q1": "",
        "q2": "",
    }
    assert data["data"] == '{"JSON":"body"}'
    assert data["json"] == {"JSON": "body"}

    request_headers = {
        "Content-Type": "application/json",
        "Content-Length": "15",
        "Custom": "headeR",
        "Host": "httpbin.org",
    }
    assert all(v == data["headers"][k] for k, v in request_headers.items())


@pytest.mark.asyncio
async def test_node(httpbin_node_config):
    def new_node(**kwargs):
        return AiohttpHttpNode(dataclasses.replace(httpbin_node_config, **kwargs))

    node = new_node()
    resp, data = await node.perform_request("GET", "/anything")
    assert resp.status == 200
    parsed = parse_httpbin(data)
    assert parsed == {
        "headers": {
            "Host": "httpbin.org",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        "method": "GET",
        "url": "https://httpbin.org/anything",
    }

    node = new_node(http_compress=True)
    resp, data = await node.perform_request("GET", "/anything")
    assert resp.status == 200
    parsed = parse_httpbin(data)
    assert parsed == {
        "headers": {
            "Accept-Encoding": "gzip",
            "Host": "httpbin.org",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        "method": "GET",
        "url": "https://httpbin.org/anything",
    }

    resp, data = await node.perform_request("GET", "/anything", body=b"hello, world!")
    assert resp.status == 200
    parsed = parse_httpbin(data)
    assert parsed == {
        "headers": {
            "Accept-Encoding": "gzip",
            "Content-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Content-Length": "33",
            "Host": "httpbin.org",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        "method": "GET",
        "url": "https://httpbin.org/anything",
    }

    resp, data = await node.perform_request(
        "POST",
        "/anything",
        body=json.dumps({"key": "value"}).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    assert resp.status == 200
    parsed = parse_httpbin(data)
    assert parsed == {
        "headers": {
            "Accept-Encoding": "gzip",
            "Content-Encoding": "gzip",
            "Content-Length": "36",
            "Content-Type": "application/json",
            "Host": "httpbin.org",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        "method": "POST",
        "url": "https://httpbin.org/anything",
    }
