# -*- coding: utf-8 -*-
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

import mock
import pytest

from elastic_transport import (
    APIError,
    ConnectionError,
    ConnectionTimeout,
    DummyConnectionPool,
    InternalServerError,
    NotFoundError,
    PaymentRequiredError,
    RequestsHttpConnection,
    Transport,
    TransportError,
    Urllib3HttpConnection,
)
from elastic_transport.response import Response
from elastic_transport.utils import DEFAULT
from tests.conftest import DummyConnection


def test_transport_close_connection_pool():
    t = Transport([{}])
    with mock.patch.object(t.connection_pool, "close") as cp_close:
        t.close()
        cp_close.assert_called_with()


def test_single_connection_uses_dummy_connection_pool():
    t = Transport([{}])
    assert isinstance(t.connection_pool, DummyConnectionPool)
    t = Transport([{"host": "localhost"}])
    assert isinstance(t.connection_pool, DummyConnectionPool)


def test_request_timeout_extracted_from_params_and_passed():
    t = Transport([{}], connection_class=DummyConnection)

    t.perform_request("GET", "/", request_timeout=42)
    assert 1 == len(t.get_connection().calls)
    assert ("GET", "/", None, None) == t.get_connection().calls[0][0]
    assert {
        "request_timeout": 42,
        "ignore_status": (),
        "headers": {},
    } == t.get_connection().calls[0][1]


def test_opaque_id():
    t = Transport([{}], opaque_id="app-1", connection_class=DummyConnection)

    t.perform_request("GET", "/")
    assert 1 == len(t.get_connection().calls)
    assert ("GET", "/", None, None) == t.get_connection().calls[0][0]
    assert {
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {},
    } == t.get_connection().calls[0][1]

    # Now try with an 'x-opaque-id' set on perform_request().
    t.perform_request("GET", "/", headers={"x-opaque-id": "request-1"})
    assert 2 == len(t.get_connection().calls)
    assert ("GET", "/", None, None) == t.get_connection().calls[1][0]
    assert {
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"x-opaque-id": "request-1"},
    } == t.get_connection().calls[1][1]


def test_ignore_status_as_int():
    t = Transport([{}], connection_class=DummyConnection)

    t.perform_request("GET", "/", ignore_status=500)
    assert 1 == len(t.get_connection().calls)
    assert ("GET", "/", None, None) == t.get_connection().calls[0][0]
    assert {
        "request_timeout": DEFAULT,
        "ignore_status": (500,),
        "headers": {},
    } == t.get_connection().calls[0][1]


def test_request_with_custom_user_agent_header():
    t = Transport([{}], connection_class=DummyConnection)

    t.perform_request("GET", "/", headers={"user-agent": "my-custom-value/1.2.3"})
    assert 1 == len(t.get_connection().calls)
    assert {
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"user-agent": "my-custom-value/1.2.3"},
    } == t.get_connection().calls[0][1]


def test_body_gets_encoded_into_bytes():
    t = Transport([{}], connection_class=DummyConnection)

    t.perform_request("GET", "/", body="你好")
    assert 1 == len(t.get_connection().calls)
    assert ("GET", "/", None, b"\xe4\xbd\xa0\xe5\xa5\xbd") == t.get_connection().calls[
        0
    ][0]


def test_body_bytes_get_passed_untouched():
    t = Transport([{}], connection_class=DummyConnection)

    body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
    t.perform_request("GET", "/", body=body)
    assert 1 == len(t.get_connection().calls)
    assert ("GET", "/", None, body) == t.get_connection().calls[0][0]


def test_body_surrogates_replaced_encoded_into_bytes():
    t = Transport([{}], connection_class=DummyConnection)

    t.perform_request("GET", "/", body=u"你好\uda6a")
    assert 1 == len(t.get_connection().calls)
    assert (
        "GET",
        "/",
        None,
        b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa",
    ) == t.get_connection().calls[0][0]


def test_kwargs_passed_on_to_connections():
    t = Transport([{"host": "example.com"}], port=123)
    assert 1 == len(t.connection_pool.connections)
    conn = t.connection_pool.connections[0]
    assert conn.base_url == "http://example.com:123"
    assert conn.scheme == "http"
    assert conn.port == 123
    assert conn.host == "example.com"


def test_kwargs_passed_on_to_connection_pool():
    dt = object()
    t = Transport([{}, {}], dead_timeout=dt)
    assert dt is t.connection_pool.dead_timeout


def test_custom_connection_class():
    class MyConnection(object):
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    t = Transport([{}], connection_class=MyConnection)
    assert 1 == len(t.connection_pool.connections)
    assert isinstance(t.connection_pool.connections[0], MyConnection)


def test_add_connection():
    t = Transport([{}], randomize_hosts=False)
    t.add_connection({"host": "example.com", "port": 1234})

    assert 2 == len(t.connection_pool.connections)
    assert "http://example.com:1234" == t.connection_pool.connections[1].base_url


def test_request_will_fail_after_X_retries():
    t = Transport(
        [{"exception": ConnectionError("abandon ship")}],
        connection_class=DummyConnection,
    )

    with pytest.raises(ConnectionError) as e:
        t.perform_request("GET", "/")
    assert 4 == len(t.get_connection().calls)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


@pytest.mark.parametrize("retry_on_timeout", [True, False])
def test_retry_on_timeout(retry_on_timeout):
    t = Transport(
        [
            {"exception": ConnectionTimeout("abandon ship")},
            {"exception": InternalServerError("")},
        ],
        connection_class=DummyConnection,
        retry_on_timeout=retry_on_timeout,
        randomize_hosts=False,
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
        assert e.value.status is None


def test_retry_on_status():
    t = Transport(
        [
            {"exception": NotFoundError("")},
            {"exception": InternalServerError("")},
            {"exception": PaymentRequiredError("")},
            {"exception": APIError("", status=555)},
        ],
        connection_class=DummyConnection,
        selector_class="round_robin",
        retry_on_status=(402, 404, 500),
        randomize_hosts=False,
        max_retries=5,
    )

    with pytest.raises(APIError) as e:
        t.perform_request("GET", "/")
    assert e.value.status == 555
    assert len(e.value.errors) == 3
    assert set([err.status for err in e.value.errors]) == {404, 500, 402}


def test_failed_connection_will_be_marked_as_dead():
    t = Transport(
        [{"exception": ConnectionError("abandon ship")}] * 2,
        connection_class=DummyConnection,
    )

    with pytest.raises(ConnectionError) as e:
        t.perform_request("GET", "/")
    assert 0 == len(t.connection_pool.connections)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


def test_resurrected_connection_will_be_marked_as_live_on_success():
    for method in ("GET", "HEAD"):
        t = Transport([{}, {}], connection_class=DummyConnection)
        con1 = t.connection_pool.get_connection()
        con2 = t.connection_pool.get_connection()
        t.connection_pool.mark_dead(con1)
        t.connection_pool.mark_dead(con2)

        t.perform_request(method, "/")
        assert 1 == len(t.connection_pool.connections)
        assert 1 == len(t.connection_pool.dead_count)


def test_mark_dead_error_doesnt_raise():
    t = Transport(
        [{"exception": APIError("502", status=502)}, {}],
        retry_on_status=(502,),
        connection_class=DummyConnection,
        randomize_hosts=False,
    )
    bad_conn = t.connection_pool.connections[0]
    with mock.patch.object(t, "mark_dead") as mark_dead:
        mark_dead.side_effect = TransportError("sniffing error!")
        t.perform_request("GET", "/")
    mark_dead.assert_called_with(bad_conn)


def test_connection_class_as_string():
    t = Transport(connection_class="urllib3")
    assert isinstance(t.connection_pool.connections[0], Urllib3HttpConnection)

    t = Transport(connection_class="requests")
    assert isinstance(t.connection_pool.connections[0], RequestsHttpConnection)

    with pytest.raises(ValueError) as e:
        Transport(connection_class="huh?")
    assert str(e.value) == (
        "Unknown option for connection_class: 'huh?'. "
        "Available options are: 'requests', 'urllib3'"
    )


def test_no_hosts_or_default_hosts():
    t = Transport()
    conns = t.connection_pool.connections
    assert len(conns) == 1
    assert conns[0].host == "localhost"
    assert conns[0].port is None
    assert conns[0].base_url == "http://localhost"


def test_default_hosts():
    t = Transport(default_hosts=[{"host": "localhost", "port": 3002, "use_ssl": False}])
    conns = t.connection_pool.connections
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
    conns = t.connection_pool.connections
    assert len(conns) == 1
    assert conns[0].base_url == base_url
    assert "[" not in conns[0].host  # Make sure [] are stripped from IPv6
    assert conns[0].port is None or isinstance(conns[0].port, int)
    assert conns[0].url_prefix == url_prefix
    assert conns[0].use_ssl == conns[0].base_url.startswith("https://")


def test_response_and_request():
    t = Transport(
        [{"headers": {"c": "d"}, "body": b'{"e": ["f"]}'}],
        connection_class=DummyConnection,
    )
    resp = t.perform_request("POST", "/url/path", params={"k": "v"}, headers={"a": "b"})
    assert isinstance(resp, Response)
    assert resp.status == 200
    assert resp.headers == {"c": "d"}
    assert resp.body == resp == {"e": ["f"]}

    t = Transport(
        [{"body": b"[1,2,3]"}],
        connection_class=DummyConnection,
    )
    resp = t.perform_request("POST", "/url/path", params={"k": "v"}, headers={"a": "b"})
    assert isinstance(resp, Response)
    assert resp.status == 200
    assert resp.body == resp == [1, 2, 3]


@pytest.mark.parametrize(["status", "boolean"], [(200, True), (299, True)])
def test_head_response_true(status, boolean):
    t = Transport([{"status": status}], connection_class=DummyConnection)
    resp = t.perform_request("HEAD", "/")
    assert resp.status == status
    assert resp == boolean
    assert resp.body is boolean
    assert bool(resp) is boolean


@pytest.mark.parametrize("exception", [NotFoundError(""), APIError("", status=404)])
def test_head_response_false(exception):
    t = Transport([{"exception": exception}], connection_class=DummyConnection)
    resp = t.perform_request("HEAD", "/")
    assert resp.status == 404
    assert resp == False  # noqa
    assert resp.body is False
    assert bool(resp) is False


@pytest.mark.parametrize("status", [300, 400, 404, 500])
def test_head_response_ignore_status(status):
    t = Transport([{"status": status}], connection_class=DummyConnection)
    resp = t.perform_request("HEAD", "/", ignore_status=(status,))
    assert resp == False  # noqa
    assert resp.body is False
    assert bool(resp) is False
