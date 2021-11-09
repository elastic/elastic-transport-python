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

import pytest

from elastic_transport import HttpHeaders, NodeConfig


def test_empty_node_config():
    config = NodeConfig(scheme="https", host="localhost", port=9200)

    assert dataclasses.asdict(config) == {
        "ca_certs": None,
        "client_cert": None,
        "client_key": None,
        "connections_per_node": 10,
        "headers": {},
        "host": "localhost",
        "http_compress": False,
        "path_prefix": "",
        "port": 9200,
        "request_timeout": 10,
        "scheme": "https",
        "ssl_assert_fingerprint": None,
        "ssl_assert_hostname": None,
        "ssl_context": None,
        "ssl_show_warn": True,
        "ssl_version": None,
        "verify_certs": True,
        "_extras": {},
    }

    # Default HttpHeaders should be empty and frozen
    assert len(config.headers) == 0
    assert config.headers.frozen


def test_headers_frozen():
    headers = HttpHeaders()
    assert headers.frozen is False

    headers["key"] = "value"
    headers.pop("Key")

    headers["key"] = "value"
    assert headers.freeze() is headers
    assert headers.frozen is True

    with pytest.raises(ValueError) as e:
        headers["key"] = "value"
    assert str(e.value) == "Can't modify headers that have been frozen"

    with pytest.raises(ValueError) as e:
        headers.pop("key")
    assert str(e.value) == "Can't modify headers that have been frozen"
    assert len(headers) == 1
    assert headers == {"key": "value"}

    assert headers.copy() is not headers
    assert headers.copy().frozen is False


@pytest.mark.parametrize(
    ["headers", "string"],
    [
        ({"field": "value"}, "{'field': 'value'}"),
        ({"Authorization": "value"}, "{'Authorization': '<hidden>'}"),
        ({"authorization": "Basic"}, "{'authorization': '<hidden>'}"),
        ({"authorization": "Basic abc"}, "{'authorization': 'Basic <hidden>'}"),
        ({"authorization": "ApiKey abc"}, "{'authorization': 'ApiKey <hidden>'}"),
        ({"authorization": "Bearer abc"}, "{'authorization': 'Bearer <hidden>'}"),
    ],
)
def test_headers_hide_auth(headers, string):
    assert repr(HttpHeaders(headers)) == string
