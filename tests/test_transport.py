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
    NodeConfig,
    NotFoundError,
    RequestsHttpNode,
    Transport,
    TransportError,
    Urllib3HttpNode,
)
from elastic_transport.client_utils import DEFAULT
from tests.conftest import DummyNode


def test_transport_close_node_pool():
    t = Transport([NodeConfig("http", "localhost", 443)])
    with mock.patch.object(t.node_pool.all()[0], "close") as node_close:
        t.close()
    node_close.assert_called_with()


def test_request_with_custom_user_agent_header():
    t = Transport([NodeConfig("http", "localhost", 80)], node_class=DummyNode)

    t.perform_request("GET", "/", headers={"user-agent": "my-custom-value/1.2.3"})
    assert 1 == len(t.node_pool.get().calls)
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"user-agent": "my-custom-value/1.2.3"},
    } == t.node_pool.get().calls[0][1]


def test_body_gets_encoded_into_bytes():
    t = Transport([NodeConfig("http", "localhost", 80)], node_class=DummyNode)

    t.perform_request(
        "GET", "/", headers={"Content-type": "application/json"}, body={"key": "你好"}
    )
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b'{"key":"\xe4\xbd\xa0\xe5\xa5\xbd"}'


def test_body_bytes_get_passed_untouched():
    t = Transport([NodeConfig("http", "localhost", 80)], node_class=DummyNode)

    body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
    t.perform_request(
        "GET", "/", body=body, headers={"Content-Type": "application/json"}
    )
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b"\xe4\xbd\xa0\xe5\xa5\xbd"


def test_kwargs_passed_on_to_node_pool():
    dt = object()
    t = Transport(
        [NodeConfig("http", "localhost", 80)],
        dead_backoff_factor=dt,
        max_dead_backoff=dt,
    )
    assert dt is t.node_pool.dead_backoff_factor
    assert dt is t.node_pool.max_dead_backoff


def test_request_will_fail_after_x_retries():
    t = Transport(
        [
            NodeConfig(
                "http",
                "localhost",
                80,
                _extras={"exception": ConnectionError("abandon ship")},
            )
        ],
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
            NodeConfig(
                "http",
                "localhost",
                80,
                _extras={"exception": ConnectionTimeout("abandon ship")},
            ),
            NodeConfig(
                "http", "localhost", 81, _extras={"exception": InternalServerError("")}
            ),
        ],
        node_class=DummyNode,
        retry_on_timeout=retry_on_timeout,
        randomize_nodes_in_pool=False,
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
            NodeConfig("http", "localhost", 80, _extras={"status": 404}),
            NodeConfig(
                "http",
                "localhost",
                81,
                _extras={"status": 401},
            ),
            NodeConfig(
                "http",
                "localhost",
                82,
                _extras={"status": 403},
            ),
            NodeConfig(
                "http",
                "localhost",
                83,
                _extras={"status": 555},
            ),
        ],
        node_class=DummyNode,
        node_selector_class="round_robin",
        retry_on_status=(401, 403, 404),
        randomize_nodes_in_pool=False,
        max_retries=5,
    )

    with pytest.raises(ApiError) as e:
        t.perform_request("GET", "/")
    assert e.value.status == 555
    assert len(e.value.errors) == 3
    assert {err.status for err in e.value.errors} == {401, 403, 404}


def test_failed_connection_will_be_marked_as_dead():
    t = Transport(
        [
            NodeConfig(
                "http",
                "localhost",
                80,
                _extras={"exception": ConnectionError("abandon ship")},
            ),
            NodeConfig(
                "http",
                "localhost",
                81,
                _extras={"exception": ConnectionError("abandon ship")},
            ),
        ],
        max_retries=3,
        node_class=DummyNode,
    )

    with pytest.raises(ConnectionError) as e:
        t.perform_request("GET", "/")
    assert 0 == len(t.node_pool.alive_nodes)
    assert 2 == len(t.node_pool.dead_nodes.queue)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


def test_resurrected_connection_will_be_marked_as_live_on_success():
    for method in ("GET", "HEAD"):
        t = Transport(
            [
                NodeConfig("http", "localhost", 80),
                NodeConfig("http", "localhost", 81),
            ],
            node_class=DummyNode,
        )
        node1 = t.node_pool.get()
        node2 = t.node_pool.get()
        t.node_pool.mark_dead(node1)
        t.node_pool.mark_dead(node2)

        t.perform_request(method, "/")
        assert 1 == len(t.node_pool.alive_nodes)
        assert 1 == len(t.node_pool.dead_consecutive_failures)
        assert 1 == len(t.node_pool.dead_nodes.queue)


def test_mark_dead_error_doesnt_raise():
    t = Transport(
        [
            NodeConfig("http", "localhost", 80, _extras={"status": 502}),
            NodeConfig("http", "localhost", 81),
        ],
        retry_on_status=(502,),
        node_class=DummyNode,
        randomize_nodes_in_pool=False,
    )
    bad_node = t.node_pool.all_nodes[NodeConfig("http", "localhost", 80)]
    with mock.patch.object(t, "mark_dead") as mark_dead:
        mark_dead.side_effect = TransportError("sniffing error!")
        t.perform_request("GET", "/")
    mark_dead.assert_called_with(bad_node)


def test_node_class_as_string():
    t = Transport([NodeConfig("http", "localhost", 80)], node_class="urllib3")
    assert isinstance(t.node_pool.get(), Urllib3HttpNode)

    t = Transport([NodeConfig("http", "localhost", 80)], node_class="requests")
    assert isinstance(t.node_pool.get(), RequestsHttpNode)

    with pytest.raises(ValueError) as e:
        Transport([NodeConfig("http", "localhost", 80)], node_class="huh?")
    assert str(e.value) == (
        "Unknown option for node_class: 'huh?'. "
        "Available options are: 'aiohttp', 'requests', 'urllib3'"
    )


@pytest.mark.parametrize(["status", "boolean"], [(200, True), (299, True)])
def test_head_response_true(status, boolean):
    t = Transport(
        [NodeConfig("http", "localhost", 80, _extras={"status": status, "body": b""})],
        node_class=DummyNode,
    )
    resp, data = t.perform_request("HEAD", "/")
    assert resp.status == status
    assert data is None


def test_head_response_false():
    t = Transport(
        [NodeConfig("http", "localhost", 80, _extras={"status": 404, "body": b""})],
        node_class=DummyNode,
    )
    with pytest.raises(NotFoundError) as e:
        t.perform_request("HEAD", "/")
    assert e.value.status == 404
    # 404s don't count as a dead node status.
    assert 0 == len(t.node_pool.dead_nodes.queue)


@pytest.mark.parametrize(
    "node_class",
    ["urllib3", "requests", Urllib3HttpNode, RequestsHttpNode],
)
def test_transport_client_meta_node_class(node_class):
    t = Transport([NodeConfig("http", "localhost", 80)], node_class=node_class)
    assert t._transport_client_meta[2] == t.node_pool.node_class._ELASTIC_CLIENT_META
    assert t._transport_client_meta[2][0] in ("ur", "rq")
    assert re.match(
        r"^py=[0-9.]+p?,t=[0-9.]+p?,(?:ur|rq)=[0-9.]+p?$",
        ",".join(f"{k}={v}" for k, v in t._transport_client_meta),
    )

    # Defaults to urllib3
    t = Transport([NodeConfig("http", "localhost", 80)])
    assert t._transport_client_meta[2][0] == "ur"
    assert [x[0] for x in t._transport_client_meta[:2]] == ["py", "t"]
