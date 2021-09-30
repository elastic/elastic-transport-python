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

import asyncio
import random
import re
import sys
import time
import warnings
from unittest import mock

import pytest

from elastic_transport import (
    AiohttpHttpNode,
    ApiError,
    AsyncTransport,
    ConnectionError,
    ConnectionTimeout,
    InternalServerError,
    NodeConfig,
    NotFoundError,
    SniffOptions,
    TransportError,
    TransportWarning,
)
from elastic_transport._compat import get_running_loop
from elastic_transport._node._base import DEFAULT_USER_AGENT
from elastic_transport.client_utils import DEFAULT
from tests.conftest import AsyncDummyNode

pytestmark = pytest.mark.asyncio


async def test_async_transport_httpbin(httpbin_node_config):
    t = AsyncTransport([httpbin_node_config])
    resp, data = await t.perform_request("GET", "/anything?key=value")

    assert resp.status == 200
    assert data["method"] == "GET"
    assert data["url"] == "https://httpbin.org/anything?key=value"
    assert data["args"] == {"key": "value"}

    data["headers"].pop("X-Amzn-Trace-Id", None)
    assert data["headers"] == {"User-Agent": DEFAULT_USER_AGENT, "Host": "httpbin.org"}


@pytest.mark.skipif(
    sys.version_info < (3, 8), reason="Mock didn't support async before Python 3.8"
)
async def test_transport_close_node_pool():
    t = AsyncTransport([NodeConfig("http", "localhost", 443)])
    with mock.patch.object(t.node_pool.all()[0], "close") as node_close:
        await t.close()
    node_close.assert_called_with()


async def test_request_with_custom_user_agent_header():
    t = AsyncTransport([NodeConfig("http", "localhost", 80)], node_class=AsyncDummyNode)

    await t.perform_request("GET", "/", headers={"user-agent": "my-custom-value/1.2.3"})
    assert 1 == len(t.node_pool.get().calls)
    assert {
        "body": None,
        "request_timeout": DEFAULT,
        "ignore_status": (),
        "headers": {"user-agent": "my-custom-value/1.2.3"},
    } == t.node_pool.get().calls[0][1]


async def test_body_gets_encoded_into_bytes():
    t = AsyncTransport([NodeConfig("http", "localhost", 80)], node_class=AsyncDummyNode)

    await t.perform_request(
        "GET", "/", headers={"Content-type": "application/json"}, body={"key": "你好"}
    )
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b'{"key":"\xe4\xbd\xa0\xe5\xa5\xbd"}'


async def test_body_bytes_get_passed_untouched():
    t = AsyncTransport([NodeConfig("http", "localhost", 80)], node_class=AsyncDummyNode)

    body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
    await t.perform_request(
        "GET", "/", body=body, headers={"Content-Type": "application/json"}
    )
    calls = t.node_pool.get().calls
    assert 1 == len(calls)
    args, kwargs = calls[0]
    assert ("GET", "/") == args
    assert kwargs["body"] == b"\xe4\xbd\xa0\xe5\xa5\xbd"


def test_kwargs_passed_on_to_node_pool():
    dt = object()
    t = AsyncTransport(
        [NodeConfig("http", "localhost", 80)],
        dead_backoff_factor=dt,
        max_dead_backoff=dt,
    )
    assert dt is t.node_pool.dead_backoff_factor
    assert dt is t.node_pool.max_dead_backoff


async def test_request_will_fail_after_x_retries():
    t = AsyncTransport(
        [
            NodeConfig(
                "http",
                "localhost",
                80,
                _extras={"exception": ConnectionError("abandon ship")},
            )
        ],
        node_class=AsyncDummyNode,
    )

    with pytest.raises(ConnectionError) as e:
        await t.perform_request("GET", "/")

    assert 4 == len(t.node_pool.get().calls)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


@pytest.mark.parametrize("retry_on_timeout", [True, False])
async def test_retry_on_timeout(retry_on_timeout):
    t = AsyncTransport(
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
        node_class=AsyncDummyNode,
        retry_on_timeout=retry_on_timeout,
        randomize_nodes_in_pool=False,
    )

    if retry_on_timeout:
        with pytest.raises(InternalServerError) as e:
            await t.perform_request("GET", "/")
        assert len(e.value.errors) == 1
        assert e.value.status == 500
        assert isinstance(e.value.errors[0], ConnectionTimeout)

    else:
        with pytest.raises(ConnectionTimeout) as e:
            await t.perform_request("GET", "/")
        assert len(e.value.errors) == 0


async def test_retry_on_status():
    t = AsyncTransport(
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
        node_class=AsyncDummyNode,
        node_selector_class="round_robin",
        retry_on_status=(401, 403, 404),
        randomize_nodes_in_pool=False,
        max_retries=5,
    )

    with pytest.raises(ApiError) as e:
        await t.perform_request("GET", "/")
    assert e.value.status == 555
    assert len(e.value.errors) == 3
    assert {err.status for err in e.value.errors} == {401, 403, 404}


async def test_failed_connection_will_be_marked_as_dead():
    t = AsyncTransport(
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
        node_class=AsyncDummyNode,
    )

    with pytest.raises(ConnectionError) as e:
        await t.perform_request("GET", "/")
    assert 0 == len(t.node_pool.alive_nodes)
    assert 2 == len(t.node_pool.dead_nodes.queue)
    assert len(e.value.errors) == 3
    assert all(isinstance(error, ConnectionError) for error in e.value.errors)


async def test_resurrected_connection_will_be_marked_as_live_on_success():
    for method in ("GET", "HEAD"):
        t = AsyncTransport(
            [
                NodeConfig("http", "localhost", 80),
                NodeConfig("http", "localhost", 81),
            ],
            node_class=AsyncDummyNode,
        )
        node1 = t.node_pool.get()
        node2 = t.node_pool.get()
        t.node_pool.mark_dead(node1)
        t.node_pool.mark_dead(node2)

        await t.perform_request(method, "/")
        assert 1 == len(t.node_pool.alive_nodes)
        assert 1 == len(t.node_pool.dead_consecutive_failures)
        assert 1 == len(t.node_pool.dead_nodes.queue)


async def test_mark_dead_error_doesnt_raise():
    t = AsyncTransport(
        [
            NodeConfig("http", "localhost", 80, _extras={"status": 502}),
            NodeConfig("http", "localhost", 81),
        ],
        retry_on_status=(502,),
        node_class=AsyncDummyNode,
        randomize_nodes_in_pool=False,
    )
    bad_node = t.node_pool.all_nodes[NodeConfig("http", "localhost", 80)]
    with mock.patch.object(t.node_pool, "mark_dead") as mark_dead, mock.patch.object(
        t, "sniff"
    ) as sniff:
        sniff.side_effect = TransportError("sniffing error!")
        await t.perform_request("GET", "/")
    mark_dead.assert_called_with(bad_node)


async def test_node_class_as_string():
    t = AsyncTransport([NodeConfig("http", "localhost", 80)], node_class="aiohttp")
    assert isinstance(t.node_pool.get(), AiohttpHttpNode)

    with pytest.raises(ValueError) as e:
        AsyncTransport([NodeConfig("http", "localhost", 80)], node_class="huh?")
    assert str(e.value) == (
        "Unknown option for node_class: 'huh?'. "
        "Available options are: 'aiohttp', 'requests', 'urllib3'"
    )


@pytest.mark.parametrize(["status", "boolean"], [(200, True), (299, True)])
async def test_head_response_true(status, boolean):
    t = AsyncTransport(
        [NodeConfig("http", "localhost", 80, _extras={"status": status, "body": b""})],
        node_class=AsyncDummyNode,
    )
    resp, data = await t.perform_request("HEAD", "/")
    assert resp.status == status
    assert data is None


async def test_head_response_false():
    t = AsyncTransport(
        [NodeConfig("http", "localhost", 80, _extras={"status": 404, "body": b""})],
        node_class=AsyncDummyNode,
    )
    with pytest.raises(NotFoundError) as e:
        await t.perform_request("HEAD", "/")
    assert e.value.status == 404
    # 404s don't count as a dead node status.
    assert 0 == len(t.node_pool.dead_nodes.queue)


@pytest.mark.parametrize(
    "node_class",
    ["aiohttp", AiohttpHttpNode],
)
async def test_transport_client_meta_node_class(node_class):
    t = AsyncTransport([NodeConfig("http", "localhost", 80)], node_class=node_class)
    assert t._transport_client_meta[2] == t.node_pool.node_class._ELASTIC_CLIENT_META
    assert t._transport_client_meta[2][0] == "ai"
    assert re.match(
        r"^py=[0-9.]+p?,t=[0-9.]+p?,ai=[0-9.]+p?$",
        ",".join(f"{k}={v}" for k, v in t._transport_client_meta),
    )

    # Defaults to aiohttp
    t = AsyncTransport([NodeConfig("http", "localhost", 80)])
    assert t._transport_client_meta[2][0] == "ai"
    assert [x[0] for x in t._transport_client_meta[:2]] == ["py", "t"]


async def test_sniff_on_start():
    calls = []

    def sniff_callback(*args):
        nonlocal calls
        calls.append(args)
        return []

    t = AsyncTransport(
        [NodeConfig("http", "localhost", 80)],
        node_class=AsyncDummyNode,
        sniff_on_start=True,
        sniff_callback=sniff_callback,
    )
    assert len(calls) == 0
    await t._async_init()
    assert len(calls) == 1

    await t.perform_request("GET", "/")

    assert len(calls) == 1
    transport, sniff_options = calls[0]
    assert transport is t
    assert sniff_options == SniffOptions(is_initial_sniff=True, sniff_timeout=1.0)


async def test_sniff_before_requests():
    calls = []

    def sniff_callback(*args):
        nonlocal calls
        calls.append(args)
        return []

    t = AsyncTransport(
        [NodeConfig("http", "localhost", 80)],
        node_class=AsyncDummyNode,
        sniff_before_requests=True,
        sniff_callback=sniff_callback,
    )
    assert len(calls) == 0

    await t.perform_request("GET", "/")
    await t._sniffing_task

    assert len(calls) == 1
    transport, sniff_options = calls[0]
    assert transport is t
    assert sniff_options == SniffOptions(is_initial_sniff=False, sniff_timeout=1.0)


async def test_sniff_on_node_failure():
    calls = []

    def sniff_callback(*args):
        nonlocal calls
        calls.append(args)
        return []

    t = AsyncTransport(
        [
            NodeConfig("http", "localhost", 80),
            NodeConfig("http", "localhost", 81, _extras={"status": 500}),
        ],
        randomize_nodes_in_pool=False,
        node_selector_class="round_robin",
        node_class=AsyncDummyNode,
        max_retries=1,
        sniff_on_node_failure=True,
        sniff_callback=sniff_callback,
    )
    assert t._sniffing_task is None
    assert len(calls) == 0

    await t.perform_request("GET", "/")
    assert t._sniffing_task is None
    assert len(calls) == 0

    with pytest.raises(InternalServerError):
        await t.perform_request("GET", "/")

    await t._sniffing_task
    assert len(calls) == 1
    transport, sniff_options = calls[0]
    assert transport is t
    assert sniff_options == SniffOptions(is_initial_sniff=False, sniff_timeout=1.0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"sniff_on_start": True},
        {"sniff_on_node_failure": True},
        {"sniff_before_requests": True},
    ],
)
async def test_error_with_sniffing_enabled_without_callback(kwargs):
    with pytest.raises(ValueError) as e:
        AsyncTransport([NodeConfig("http", "localhost", 80)], **kwargs)

    assert str(e.value) == "Enabling sniffing requires specifying a 'sniff_callback'"


async def test_error_sniffing_callback_without_sniffing_enabled():
    with pytest.raises(ValueError) as e:
        AsyncTransport(
            [NodeConfig("http", "localhost", 80)], sniff_callback=lambda *_: []
        )

    assert str(e.value) == (
        "Using 'sniff_callback' requires enabling sniffing via 'sniff_on_start', "
        "'sniff_before_requests' or 'sniff_on_node_failure'"
    )


async def test_heterogeneous_node_config_warning_with_sniffing():
    with warnings.catch_warnings(record=True) as w:
        AsyncTransport(
            [
                NodeConfig("http", "localhost", 80, path_prefix="/a"),
                NodeConfig("http", "localhost", 81, path_prefix="/b"),
            ],
            sniff_on_start=True,
            sniff_callback=lambda *_: [],
        )

    assert len(w) == 1
    assert w[0].category == TransportWarning
    assert str(w[0].message) == (
        "Detected NodeConfig instances with different options. It's "
        "recommended to keep all options except for 'host' and 'port' "
        "the same for sniffing to work reliably."
    )


@pytest.mark.parametrize("async_sniff_callback", [True, False])
async def test_sniffed_nodes_added_to_pool(async_sniff_callback):
    sniffed_nodes = [
        NodeConfig("http", "localhost", 80),
        NodeConfig("http", "localhost", 81),
    ]

    loop = get_running_loop()
    sniffed_at = 0.0

    # Test that we accept both sync and async sniff_callbacks
    if async_sniff_callback:

        async def sniff_callback(*_):
            nonlocal loop, sniffed_at
            await asyncio.sleep(0.1)
            sniffed_at = loop.time()
            return sniffed_nodes

    else:

        def sniff_callback(*_):
            nonlocal loop, sniffed_at
            time.sleep(0.1)
            sniffed_at = loop.time()
            return sniffed_nodes

    t = AsyncTransport(
        [
            NodeConfig("http", "localhost", 80),
        ],
        node_class=AsyncDummyNode,
        sniff_before_requests=True,
        sniff_callback=sniff_callback,
    )
    assert len(t.node_pool.all_nodes) == 1

    request_at = loop.time()
    await t.perform_request("GET", "/")
    response_at = loop.time()
    await t._sniffing_task

    assert 0.1 <= (sniffed_at - request_at) <= 0.15
    assert 0 <= response_at - request_at < 0.05

    # The node pool knows when nodes are already in the pool
    # so we shouldn't get duplicates after sniffing.
    assert len(t.node_pool.all_nodes) == 2
    assert set(sniffed_nodes) == set(t.node_pool.all_nodes)


async def test_sniff_error_resets_lock_and_last_sniffed_at():
    def sniff_error(*_):
        raise TransportError("This is an error!")

    t = AsyncTransport(
        [
            NodeConfig("http", "localhost", 80),
        ],
        node_class=AsyncDummyNode,
        sniff_on_start=True,
        sniff_callback=sniff_error,
    )
    last_sniffed_at = t._last_sniffed_at

    with pytest.raises(TransportError) as e:
        await t.perform_request("GET", "/")
    assert str(e.value) == "This is an error!"

    assert t._last_sniffed_at == last_sniffed_at
    assert t._sniffing_task.done()


@pytest.mark.parametrize("pool_size", [1, 8])
async def test_multiple_tasks_test(pool_size):
    node_configs = [
        NodeConfig("http", "localhost", 80),
        NodeConfig("http", "localhost", 81),
        NodeConfig("http", "localhost", 82),
        NodeConfig("http", "localhost", 83, _extras={"status": 500}),
    ]

    async def sniff_callback(*_):
        await asyncio.sleep(random.random())
        return node_configs

    t = AsyncTransport(
        node_configs,
        retry_on_status=[500],
        max_retries=5,
        node_class=AsyncDummyNode,
        sniff_on_start=True,
        sniff_before_requests=True,
        sniff_on_node_failure=True,
        sniff_callback=sniff_callback,
    )

    loop = get_running_loop()
    start = loop.time()

    async def run_requests():
        successful_requests = 0
        while loop.time() - start < 2:
            await t.perform_request("GET", "/")
            successful_requests += 1
        return successful_requests

    tasks = [loop.create_task(run_requests()) for _ in range(pool_size * 2)]
    assert sum([await task for task in tasks]) >= 1000
