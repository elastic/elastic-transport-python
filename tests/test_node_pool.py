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


import random
import threading
import time

import pytest

from elastic_transport import NodeConfig, NodePool, Urllib3HttpNode


def test_node_pool_repr():
    node_configs = [NodeConfig("http", "localhost", x) for x in range(5)]
    random.shuffle(node_configs)
    pool = NodePool(node_configs, node_class=Urllib3HttpNode)
    assert repr(pool) == "<NodePool>"


def test_node_pool_empty_error():
    with pytest.raises(ValueError) as e:
        NodePool([], node_class=Urllib3HttpNode)
    assert str(e.value) == "Must specify at least one NodeConfig"


def test_node_pool_duplicate_node_configs():
    node_config = NodeConfig("http", "localhost", 80)
    with pytest.raises(ValueError) as e:
        NodePool([node_config, node_config], node_class=Urllib3HttpNode)
    assert str(e.value) == "Cannot use duplicate NodeConfigs within a NodePool"


def test_node_pool_get():
    node_config = NodeConfig("http", "localhost", 80)
    pool = NodePool([node_config], node_class=Urllib3HttpNode)
    assert pool.get().config is node_config


def test_node_pool_remove_seed_node():
    node_config = NodeConfig("http", "localhost", 80)
    pool = NodePool([node_config], node_class=Urllib3HttpNode)

    pool.remove(node_config)  # Calling .remove() on a seed node is a no-op
    assert len(pool._removed_nodes) == 0


def test_node_pool_add_and_remove_non_seed_node():
    node_config1 = NodeConfig("http", "localhost", 80)
    node_config2 = NodeConfig("http", "localhost", 81)
    pool = NodePool([node_config1], node_class=Urllib3HttpNode)

    pool.add(node_config2)
    assert any(pool.get().config is node_config2 for _ in range(10))

    pool.remove(node_config2)
    assert len(pool._removed_nodes) == 1

    # We never return a 'removed' node
    assert all(pool.get().config is node_config1 for _ in range(10))

    # We add it back, now we should .get() the node again.
    pool.add(node_config2)
    assert any(pool.get().config is node_config2 for _ in range(10))


def test_added_node_is_used_first():
    node_config1 = NodeConfig("http", "localhost", 80)
    node_config2 = NodeConfig("http", "localhost", 81)
    pool = NodePool([node_config1], node_class=Urllib3HttpNode)

    node1 = pool.get()
    pool.mark_dead(node1)

    pool.add(node_config2)
    assert pool.get().config is node_config2


def test_round_robin_selector():
    node_configs = [NodeConfig("http", "localhost", x) for x in range(5)]
    random.shuffle(node_configs)
    pool = NodePool(
        node_configs, node_class=Urllib3HttpNode, node_selector_class="round_robin"
    )

    get_node_configs = [pool.get() for _ in node_configs]
    for node_config in get_node_configs:
        assert pool.get() is node_config


@pytest.mark.parametrize(
    "node_configs",
    [
        [NodeConfig("http", "localhost", 80)],
        [NodeConfig("http", "localhost", 80), NodeConfig("http", "localhost", 81)],
    ],
)
def test_all_dead_nodes_still_gets_node(node_configs):
    pool = NodePool(node_configs, node_class=Urllib3HttpNode)

    for _ in node_configs:
        pool.mark_dead(pool.get())
    assert len(pool._alive_nodes) == 0

    node = pool.get()
    assert node.config in node_configs
    assert len(pool._alive_nodes) < 2


def test_unknown_selector_class():
    with pytest.raises(ValueError) as e:
        NodePool(
            [NodeConfig("http", "localhost", 80)],
            node_class=Urllib3HttpNode,
            node_selector_class="unknown",
        )
    assert str(e.value) == (
        "Unknown option for selector_class: 'unknown'. "
        "Available options are: 'random', 'round_robin'"
    )


def test_disable_randomize_nodes():
    node_configs = [NodeConfig("http", "localhost", x) for x in range(100)]
    pool = NodePool(node_configs, node_class=Urllib3HttpNode, randomize_nodes=False)

    assert [pool.get().config for _ in node_configs] == node_configs


def test_nodes_randomized_by_default():
    node_configs = [NodeConfig("http", "localhost", x) for x in range(100)]
    pool = NodePool(node_configs, node_class=Urllib3HttpNode)

    assert [pool.get().config for _ in node_configs] != node_configs


def test_dead_nodes_are_skipped():
    node_configs = [NodeConfig("http", "localhost", x) for x in range(2)]
    pool = NodePool(node_configs, node_class=Urllib3HttpNode)
    dead_node = pool.get()
    pool.mark_dead(dead_node)

    alive_node = pool.get()
    assert dead_node.config != alive_node.config

    assert all([pool.get().config == alive_node.config for _ in range(10)])


def test_dead_node_backoff_calculation():
    node_configs = [NodeConfig("http", "localhost", 9200)]
    pool = NodePool(
        node_configs,
        node_class=Urllib3HttpNode,
        dead_node_backoff_factor=0.5,
        max_dead_node_backoff=3.5,
    )
    node = pool.get()
    pool.mark_dead(node, _now=0)

    assert pool._dead_consecutive_failures == {node.config: 1}
    assert pool._dead_nodes.queue == [(0.5, node)]

    assert pool.get() is node
    pool.mark_dead(node, _now=0)

    assert pool._dead_consecutive_failures == {node.config: 2}
    assert pool._dead_nodes.queue == [(1.0, node)]

    assert pool.get() is node
    pool.mark_dead(node, _now=0)

    assert pool._dead_consecutive_failures == {node.config: 3}
    assert pool._dead_nodes.queue == [(2.0, node)]

    assert pool.get() is node
    pool.mark_dead(node, _now=0)

    assert pool._dead_consecutive_failures == {node.config: 4}
    assert pool._dead_nodes.queue == [(3.5, node)]

    assert pool.get() is node
    pool.mark_dead(node, _now=0)

    pool._dead_consecutive_failures = {node.config: 13292}
    assert pool._dead_nodes.queue == [(3.5, node)]

    assert pool.get() is node
    pool.mark_live(node)

    assert pool._dead_consecutive_failures == {}
    assert pool._dead_nodes.queue == []


def test_add_node_after_sniffing():
    node_configs = [NodeConfig("http", "localhost", 9200)]
    pool = NodePool(
        node_configs,
        node_class=Urllib3HttpNode,
    )

    # Initial node is marked as dead
    node = pool.get()
    pool.mark_dead(node)

    new_node_config = NodeConfig("http", "localhost", 9201)
    pool.add(new_node_config)

    # Internal flag is updated properly
    assert pool._all_nodes_len_1 is False

    # We get the new node instead of the old one
    new_node = pool.get()
    assert new_node.config == new_node_config

    # The old node is still on timeout so we should only get the new one.
    for _ in range(10):
        assert pool.get() is new_node


@pytest.mark.parametrize("pool_size", [1, 8])
def test_threading_test(pool_size):
    pool = NodePool(
        [NodeConfig("http", "localhost", x) for x in range(pool_size)],
        node_class=Urllib3HttpNode,
    )
    start = time.time()

    class ThreadTest(threading.Thread):
        def __init__(self):
            super().__init__()
            self.nodes_gotten = 0

        def run(self) -> None:
            nonlocal pool

            while time.time() < start + 2:
                node = pool.get()
                self.nodes_gotten += 1
                if random.random() > 0.9:
                    pool.mark_dead(node)
                else:
                    pool.mark_live(node)

    threads = [ThreadTest() for _ in range(pool_size * 2)]
    [thread.start() for thread in threads]
    [thread.join() for thread in threads]

    assert sum(thread.nodes_gotten for thread in threads) >= 10000
