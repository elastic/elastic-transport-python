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

import logging
import random
import threading
import time
from queue import Empty, PriorityQueue
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union, overload

from ._models import NodeConfig
from ._node import BaseNode

logger = logging.getLogger("elastic_transport.node_pool")


class NodeSelector:
    """
    Simple class used to select a node from a list of currently live
    node instances. In init time it is passed a dictionary containing all
    the nodes options which it can then use during the selection
    process. When the `select` method is called it is given a list of
    *currently* live nodes to choose from.

    The options dictionary is the one that has been passed to
    :class:`~elastic_transport.Transport` as `hosts` param and the same that is
    used to construct the Connection object itself. When the Connection was
    created from information retrieved from the cluster via the sniffing
    process it will be the dictionary returned by the `host_info_callback`.

    Example of where this would be useful is a zone-aware selector that would
    only select connections from it's own zones and only fall back to other
    connections where there would be none in its zones.
    """

    def __init__(self, node_configs):
        """
        :arg node_configs: dictionary of connection instances and their options
        """
        self.node_configs = node_configs

    def select(
        self, node_configs: Sequence[NodeConfig]
    ) -> NodeConfig:  # pragma: nocover
        """
        Select a connection from the given list.

        :arg nodes: list of live connections to choose from
        """
        raise NotImplementedError()


class RandomSelector(NodeSelector):
    """
    Select a connection at random
    """

    def select(self, node_configs: Sequence[NodeConfig]) -> NodeConfig:
        return random.choice(node_configs)


class RoundRobinSelector(NodeSelector):
    """
    Selector using round-robin.
    """

    def __init__(self, node_configs):
        super().__init__(node_configs)
        self._thread_local = threading.local()

    def select(self, node_configs: Sequence[NodeConfig]) -> NodeConfig:
        self._thread_local.rr = (getattr(self._thread_local, "rr", -1) + 1) % len(
            node_configs
        )
        return node_configs[self._thread_local.rr]


SELECTOR_CLASS_NAMES: Dict[str, Type[NodeSelector]] = {
    "round_robin": RoundRobinSelector,
    "random": RandomSelector,
}


class NodePool:
    """
    Container holding the :class:`~elastic_transport.BaseNode` instances,
    managing the selection process (via a
    :class:`~elastic_transport.NodeSelector`) and dead connections.

    It's only interactions are with the :class:`~elastic_transport.Transport` class
    that drives all the actions within ``NodePool``.

    Initially connections are stored on the class as a list and, along with the
    connection options, get passed to the ``NodeSelector`` instance for
    future reference.

    Upon each request the ``Transport`` will ask for a ``BaseNode`` via the
    ``get_node`` method. If the connection fails (it's `perform_request`
    raises a `ConnectionError`) it will be marked as dead (via `mark_dead`) and
    put on a timeout (if it fails N times in a row the timeout is exponentially
    longer - the formula is `default_timeout * 2 ** (fail_count - 1)`). When
    the timeout is over the connection will be resurrected and returned to the
    live pool. A connection that has been previously marked as dead and
    succeeds will be marked as live (its fail count will be deleted).
    """

    def __init__(
        self,
        node_configs: List[NodeConfig],
        node_class: Type[BaseNode],
        dead_timeout: float = 60,
        timeout_cutoff: float = 5,
        selector_class: Union[str, Type[NodeSelector]] = RoundRobinSelector,
        randomize_nodes: bool = True,
    ):
        """
        :arg node_configs: List of initial NodeConfigs to use
        :arg node_class: Type to use when creating nodes
        :arg dead_timeout: number of seconds a connection should be retired for
            after a failure, increases on consecutive failures
        :arg timeout_cutoff: number of consecutive failures after which the
            timeout doesn't increase
        :arg selector_class: :class:`~elastic_transport.NodeSelector`
            subclass to use if more than one connection is live
        :arg randomize_nodes: shuffle the list of nodes upon arrival to
            avoid dog piling effect across processes
        """
        if not node_configs:
            raise ValueError("Must specify at least one node instance")

        if isinstance(selector_class, str):
            if selector_class not in SELECTOR_CLASS_NAMES:
                raise ValueError(
                    "Unknown option for selector_class: '%s'. "
                    "Available options are: '%s'"
                    % (
                        selector_class,
                        "', '".join(sorted(SELECTOR_CLASS_NAMES.keys())),
                    )
                )
            selector_class = SELECTOR_CLASS_NAMES[selector_class]

        self.node_configs = node_configs
        self.node_class = node_class
        self.nodes = []

        # Remember the original set of 'NodeConfig' for use with .resurrect(force=True)
        self.seed_nodes: Tuple[NodeConfig, ...] = tuple(self.node_configs)

        # PriorityQueue for thread safety and ease of timeout management
        self.dead = PriorityQueue()
        self.dead_count = {}

        if randomize_nodes:
            # randomize the list of nodes to avoid hammering the same node
            # if a large set of clients are created all at once.
            random.shuffle(self.node_configs)

        # default timeout after which to try resurrecting a connection
        self.dead_timeout = dead_timeout
        self.timeout_cutoff = timeout_cutoff

        self.selector = selector_class(self.node_configs)

    def mark_dead(self, node: BaseNode, _now: Optional[float] = None) -> None:
        """
        Mark the node as dead (failed). Remove it from the live pool and put it on a timeout.

        :arg node: the failed instance
        """
        now: float = _now if _now is not None else time.time()
        try:
            self.node_configs.remove(node.config)
        except ValueError:
            logger.info(
                "Attempted to remove %r, but it does not exist in the node pool",
                node,
            )
            # node not alive or another thread marked it already, ignore
            return
        else:
            dead_count = self.dead_count.get(node, 0) + 1
            self.dead_count[node] = dead_count
            timeout = self.dead_timeout * 2 ** min(dead_count - 1, self.timeout_cutoff)
            self.dead.put((now + timeout, node))
            logger.warning(
                "Node %r has failed for %i times in a row, putting on %i second timeout",
                node,
                dead_count,
                timeout,
            )

    def mark_live(self, node: BaseNode) -> None:
        """
        Mark node as healthy after a resurrection. Resets the fail counter for the node.

        :arg node: The ``BaseNode`` instance to remark as alive
        """
        try:
            del self.dead_count[node.config]
        except KeyError:
            # race condition, safe to ignore
            pass

    @overload
    def resurrect(self, force: bool = True) -> BaseNode:
        ...

    def resurrect(self, force: bool = False) -> Optional[BaseNode]:
        """
        Attempt to resurrect a connection from the dead pool. It will try to
        locate one (not all) eligible (it's timeout is over) node to
        return to the live pool. Any resurrected node is also returned.

        :arg force: resurrect a connection even if there is none eligible (used
            when we have no live connections). If force is 'True'' resurrect
            always returns a connection.
        """
        # no dead connections
        if self.dead.empty():
            # we are forced to return a connection, take one from the original
            # list. This is to avoid a race condition where get_connection can
            # see no live connections but when it calls resurrect self.dead is
            # also empty. We assume that other threat has resurrected all
            # available connections so we can safely return one at random.
            if force:
                return self.new(random.choice(self.seed_nodes))
            return None

        try:
            # retrieve a connection to check
            timeout, node_config = self.dead.get(block=False)
        except Empty:
            # other thread has been faster and the queue is now empty. If we
            # are forced, return a connection at random again.
            if force:
                return self.new(random.choice(self.seed_nodes))
            return None

        if not force and timeout > time.time():
            # return it back if not eligible and not forced
            self.dead.put((timeout, node_config))
            return None

        # either we were forced or the connection is eligible to be retried
        self.node_configs.append(node_config)
        logger.info("Resurrecting node %r (force=%s)", node_config, force)
        return self.new(node_config)

    def get(self) -> BaseNode:
        """
        Return a node from the pool using the ``NodeSelector`` instance.

        It tries to resurrect eligible nodes, forces a resurrection when
        no nodes are available and passes the list of live nodes to
        the selector instance to choose from.

        Returns a node instance and it's current fail count.
        """
        self.resurrect()
        node_configs = self.node_configs[:]

        # no live nodes, resurrect one by force and return it
        if not node_configs:
            return self.resurrect(force=True)

        # only call selector if we have a selection
        if len(node_configs) > 1:
            return self.new(self.selector.select(node_configs))

        # only one connection, no need for a selector
        return self.new(node_configs[0])

    def new(self, node_config: NodeConfig) -> BaseNode:
        return self.node_class(node_config)

    def close(self) -> None:
        """
        Explicitly closes nodes
        """
        for node in self.nodes:
            node.close()

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {self.nodes!r}>"


class SingleNodePool(NodePool):
    def __init__(self, node_configs, **_):
        if len(node_configs) != 1:
            raise ValueError("SingleNodePool needs exactly one node defined.")

        # we need connection opts for sniffing logic
        self.node_configs = node_configs
        self.nodes: Tuple[BaseNode] = (self.new(node_configs[0]),)

    def get(self) -> BaseNode:
        return self.nodes[0]

    def close(self) -> None:
        """
        Explicitly closes connections
        """
        self.nodes[0].close()

    def _noop(self, *args: Any, **kwargs: Any) -> Any:
        pass

    mark_dead = mark_live = resurrect = _noop


class EmptyNodePool(NodePool):
    """A node pool that is empty. Errors out if used."""

    def __init__(self, *_, **__):
        self.nodes = []
        self.node_configs = []

    def get(self) -> BaseNode:
        raise ValueError("No nodes were configured")

    def _noop(self, *args, **kwargs):
        pass

    close = mark_dead = mark_live = resurrect = _noop
