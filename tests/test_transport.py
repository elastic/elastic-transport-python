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

import re
from unittest import mock

import pytest

from elastic_transport import (
    ApiError,
    ConnectionError,
    ConnectionTimeout,
    InternalServerError,
    NotFoundError,
    PaymentRequiredError,
    RequestsHttpNode,
    SingleNodePool,
    Transport,
    TransportError,
    Urllib3HttpNode,
)
from elastic_transport.utils import DEFAULT
from tests.conftest import DummyNode


def test_transport_close_node_pool():
    t = Transport([{}])
    with mock.patch.object(t.node_pool, "close") as node_pool_close:
        t.close()
        node_pool_close.assert_called_with()


def test_single_connection_uses_dummy_node_pool():
    t = Transport([{}])
    assert isinstance(t.node_pool, SingleNodePool)

    t = Transport([{"host": "localhost"}])
    assert isinstance(t.node_pool, SingleNodePool)


def test_request_timeout_extracted_from_params_and_passed():
    t = Transport([{}], node_class=DummyNode)

    t.perform_request("GET", "/", request_timeout=42)
    assert 1 == len(t.node_pool.get().calls)
    assert ("GET", "/") == t.node_pool.get().calls[0][0]
    assert {
        "body": None,
        "request_timeout": 42,
        "ignore_status": (),
        "headers": {},
    } == t.node_pool.get().calls[0][1]


def test_opaque_id():
    t = Transport([{}], opaque_id="app-1", node_class=DummyNode)

    t.perform_request("GET", "/")
    assert 1 == len(t.node_pool.get().calls)
    assert ("GET", "/") == t.node_pool.get().calls[0][0]
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {},
    } == t.node_pool.get().calls[0][1]

    # Now try with an 'x-opaque-id' set on perform_request().
    t.perform_request("GET", "/", headers={"x-opaque-id": "request-1"})
    assert 2 == len(t.node_pool.get().calls)
    assert ("GET", "/") == t.node_pool.get().calls[1][0]
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"x-opaque-id": "request-1"},
    } == t.node_pool.get().calls[1][1]


def test_ignore_status_as_int():
    t = Transport([{}], node_class=DummyNode)

    t.perform_request("GET", "/", ignore_status=500)
    assert 1 == len(t.node_pool.get().calls)
    assert ("GET", "/") == t.node_pool.get().calls[0][0]
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (500,),
        "headers": {},
    } == t.node_pool.get().calls[0][1]


def test_request_with_custom_user_agent_header():
    t = Transport([{}], node_class=DummyNode)

    t.perform_request("GET", "/", headers={"user-agent": "my-custom-value/1.2.3"})
    assert 1 == len(t.node_pool.get().calls)
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"user-agent": "my-custom-value/1.2.3"},
    } == t.node_pool.get().calls[0][1]


def test_body_gets_encoded_into_bytes():
    t = Transport([{}], node_class=DummyNode)

    t.perform_request("GET", "/", body={"key": "你好"})
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b'{"key":"\xe4\xbd\xa0\xe5\xa5\xbd"}'


def test_body_bytes_get_passed_untouched():
    t = Transport([{}], node_class=DummyNode)

    body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
    t.perform_request("GET", "/", body=body)
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b"\xe4\xbd\xa0\xe5\xa5\xbd"


def test_kwargs_passed_on_to_connections():
    t = Transport([{"host": "example.com"}], port=123)
    assert 1 == len(t.node_pool.nodes)
    conn = t.node_pool.nodes[0]
    assert conn.base_url == "http://example.com:123"
    assert conn.scheme == "http"
    assert conn.port == 123
    assert conn.host == "example.com"


def test_kwargs_passed_on_to_node_pool():
    dt = object()
    t = Transport([{}, {}], dead_timeout=dt)
    assert dt is t.node_pool.dead_timeout


def test_custom_node_class():
    class MyConnection:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    t = Transport([{}], node_class=MyConnection)
    assert 1 == len(t.node_pool.nodes)
    assert isinstance(t.node_pool.nodes[0], MyConnection)


def test_add_connection():
    t = Transport([{}], randomize_nodes=False)
    t.add_node({"host": "example.com", "port": 1234})

    assert 2 == len(t.node_pool.nodes)
    assert "http://example.com:1234" == t.node_pool.nodes[1].base_url


def test_request_will_fail_after_X_retries():
    t = Transport(
        [{"exception": ConnectionError("abandon ship")}],
        node_class=DummyNode,
    )

    with pytest.raises(ConnectionError) as e:
        t.perform_request("GET", "/")
    assert 4 == len(t.node_pool.get().calls)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


@pytest.mark.parametrize("retry_on_timeout", [True, False])
def test_retry_on_timeout(retry_on_timeout):
    t = Transport(
        [
            {"exception": ConnectionTimeout("abandon ship")},
            {"exception": InternalServerError("")},
        ],
        node_class=DummyNode,
        retry_on_timeout=retry_on_timeout,
        randomize_nodes=False,
    )

    if retry_on_timeout:
        with pytest.raises(InternalServerError) as e:
            t.perform_request("GET", "/")
        assert len(e.value.errors) == 1
        assert e.value.status == 500
        assert isinstance(e.value.errors[0], ConnectionTimeout)

    else:
        with pytest.raises(ConnectionTimeout) as e:
            t.perform_request("GET", "/")
        assert len(e.value.errors) == 0


def test_retry_on_status():
    t = Transport(
        [
            {"exception": NotFoundError("")},
            {"exception": InternalServerError("")},
            {"exception": PaymentRequiredError("")},
            {"exception": ApiError("", status=555)},
        ],
        node_class=DummyNode,
        selector_class="round_robin",
        retry_on_status=(402, 404, 500),
        randomize_nodes=False,
        max_retries=5,
    )

    with pytest.raises(ApiError) as e:
        t.perform_request("GET", "/")
    assert e.value.status == 555
    assert len(e.value.errors) == 3
    assert {err.status for err in e.value.errors} == {404, 500, 402}


def test_failed_connection_will_be_marked_as_dead():
    t = Transport(
        [{"exception": ConnectionError("abandon ship")}] * 2,
        node_class=DummyNode,
    )

    with pytest.raises(ConnectionError) as e:
        t.perform_request("GET", "/")
    assert 0 == len(t.node_pool.nodes)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


def test_resurrected_connection_will_be_marked_as_live_on_success():
    for method in ("GET", "HEAD"):
        t = Transport([{}, {}], node_class=DummyNode)
        con1 = t.node_pool.get()
        con2 = t.node_pool.get()
        t.node_pool.mark_dead(con1)
        t.node_pool.mark_dead(con2)

        t.perform_request(method, "/")
        assert 1 == len(t.node_pool.nodes)
        assert 1 == len(t.node_pool.dead_count)


def test_mark_dead_error_doesnt_raise():
    t = Transport(
        [{"exception": ApiError("502", status=502)}, {}],
        retry_on_status=(502,),
        node_class=DummyNode,
        randomize_nodes=False,
    )
    bad_conn = t.node_pool.nodes[0]
    with mock.patch.object(t.node_pool, "mark_dead") as mark_dead:
        mark_dead.side_effect = TransportError("sniffing error!")
        t.perform_request("GET", "/")
    mark_dead.assert_called_with(bad_conn)


def test_node_class_as_string():
    t = Transport(node_class="urllib3")
    assert isinstance(t.node_pool.nodes[0], Urllib3HttpNode)

    t = Transport(node_class="requests")
    assert isinstance(t.node_pool.nodes[0], RequestsHttpNode)

    with pytest.raises(ValueError) as e:
        Transport(node_class="huh?")
    assert str(e.value) == (
        "Unknown option for node_class: 'huh?'. "
        "Available options are: 'aiohttp', 'requests', 'urllib3'"
    )


def test_no_hosts_or_default_hosts():
    t = Transport()
    conns = t.node_pool.nodes
    assert len(conns) == 1
    assert conns[0].host == "localhost"
    assert conns[0].port is None
    assert conns[0].base_url == "http://localhost"


def test_default_hosts():
    t = Transport(default_hosts=[{"host": "localhost", "port": 3002, "use_ssl": False}])
    conns = t.node_pool.nodes
    assert len(conns) == 1
    assert conns[0].host == "localhost"
    assert conns[0].port == 3002
    assert conns[0].base_url == "http://localhost:3002"


@pytest.mark.parametrize(
    ["hosts", "base_url", "url_prefix"],
    [
        ("localhost", "http://localhost", ""),
        ("localhost:3002", "http://localhost:3002", ""),
        ("localhost/url-prefix/", "http://localhost/url-prefix", "/url-prefix"),
        (
            "localhost:3002/url-prefix",
            "http://localhost:3002/url-prefix",
            "/url-prefix",
        ),
        ("http://localhost", "http://localhost", ""),
        ("http://localhost:3002", "http://localhost:3002", ""),
        ("http://localhost/url-prefix", "http://localhost/url-prefix", "/url-prefix"),
        (
            "http://localhost:3002/url-prefix/",
            "http://localhost:3002/url-prefix",
            "/url-prefix",
        ),
        ("[::1]", "http://[::1]", ""),
        ("[::1]:3002", "http://[::1]:3002", ""),
        ("[::1]/url-prefix/", "http://[::1]/url-prefix", "/url-prefix"),
        ("[::1]:3002/url-prefix", "http://[::1]:3002/url-prefix", "/url-prefix"),
        ("localhost:0", "http://localhost:0", ""),
        ("https://[::1]:0/", "https://[::1]:0", ""),
    ],
)
def test_string_url_hosts(hosts, base_url, url_prefix):
    t = Transport(hosts)
    conns = t.node_pool.nodes
    assert len(conns) == 1
    assert conns[0].base_url == base_url
    assert "[" not in conns[0].host  # Make sure [] are stripped from IPv6
    assert conns[0].port is None or isinstance(conns[0].port, int)
    assert conns[0].url_prefix == url_prefix
    assert conns[0].use_ssl == conns[0].base_url.startswith("https://")


def test_response_and_request():
    t = Transport(
        [{"headers": {"c": "d"}, "body": b'{"e": ["f"]}'}],
        node_class=DummyNode,
    )
    resp, data = t.perform_request(
        "POST", "/url/path", params={"k": "v"}, headers={"a": "b"}
    )
    assert resp.status == 200
    assert resp.headers == {"c": "d"}
    assert data == {"e": ["f"]}

    t = Transport(
        [{"body": b"[1,2,3]"}],
        node_class=DummyNode,
    )
    resp, data = t.perform_request(
        "POST", "/url/path", params={"k": "v"}, headers={"a": "b"}
    )
    assert resp.status == 200
    assert data == [1, 2, 3]


@pytest.mark.parametrize(["status", "boolean"], [(200, True), (299, True)])
def test_head_response_true(status, boolean):
    t = Transport([{"status": status, "body": b""}], node_class=DummyNode)
    resp, data = t.perform_request("HEAD", "/")
    assert resp.status == status
    assert data is None


def test_head_response_false():
    t = Transport([{"status": 404, "body": b""}], node_class=DummyNode)
    with pytest.raises(NotFoundError) as e:
        t.perform_request("HEAD", "/")
    assert e.value.status == 404


@pytest.mark.parametrize(
    "node_class",
    ["urllib3", "requests", Urllib3HttpNode, RequestsHttpNode],
)
def test_transport_client_meta_node_class(node_class):
    t = Transport(node_class=node_class)
    assert t._transport_client_meta[2] == t.node_class._ELASTIC_CLIENT_META
    assert t._transport_client_meta[2][0] in ("ur", "rq")
    assert re.match(
        r"^py=[0-9.]+p?,t=[0-9.]+p?,(?:ur|rq)=[0-9.]+p?$",
        ",".join(f"{k}={v}" for k, v in t._transport_client_meta),
    )

    t = Transport()
    assert t._transport_client_meta[2][0] == "ur"
    assert [x[0] for x in t._transport_client_meta[:2]] == ["py", "t"]


@pytest.mark.parametrize(
    ["params", "expected"],
    [
        (None, ""),
        ({}, ""),
        ([], ""),
        ((), ""),
        ({"k": "v"}, "?k=v"),
        ({"k": 1}, "?k=1"),
        ({"k": 1.1}, "?k=1.1"),
        ({"k": b"v"}, "?k=v"),
        ({"k": "你好"}, "?k=%E4%BD%A0%E5%A5%BD"),
        ({"k": "你好".encode("utf-8")}, "?k=%E4%BD%A0%E5%A5%BD"),
        (
            {"k": r"\/"},
            "?k=%5C%2F",
        ),
        ({"k": None}, "?k"),
        ({"k": ""}, "?k="),
        ([("k1", "v1"), ("k2", "v2")], "?k1=v1&k2=v2"),
        ({"k": "value with spaces"}, "?k=value%20with%20spaces"),
        ({"k": "1234567890-_~."}, "?k=1234567890-_~."),
        (
            {"k": " `=!@#$%^&*()+[];'{}:,<>?/\\\""},
            "?k=%20%60%3D%21%40%23%24%25%5E%26%2A%28%29%2B%5B%5D%3B%27%7B%7D%3A%2C%3C%3E%3F%2F%5C%22",
        ),
    ],
)
def test_transport_default_params_encoder(params, expected):
    t = Transport(node_class=DummyNode)
    t.perform_request("GET", "/", params=params)

    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    assert ("GET", "/" + expected) == calls[0][0]


@pytest.mark.parametrize("param", [True, False, [], (), {}, object()])
def test_transport_default_encoder_type_error(param):
    t = Transport(node_class=DummyNode)

    with pytest.raises(TypeError) as e:
        t.perform_request("GET", "/", params={"key": param})
    assert (
        str(e.value)
        == "Default Transport.params_encoder supports bytes, str, int, float values or 'None'"
    )
