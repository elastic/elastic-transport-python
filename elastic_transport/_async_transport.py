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
from typing import Any, Awaitable, Callable, List, Optional, Tuple, Type, Union

from ._compat import await_if_coro, get_running_loop
from ._exceptions import (
    HTTP_STATUS_TO_ERROR,
    ApiError,
    ConnectionError,
    ConnectionTimeout,
    TransportError,
)
from ._models import ApiResponseMeta, NodeConfig, SniffOptions
from ._node import AiohttpHttpNode, BaseNode
from ._node_pool import NodePool, NodeSelector
from ._transport import (
    NOT_DEAD_NODE_HTTP_STATUSES,
    Transport,
    validate_sniffing_options,
)
from .client_utils import DEFAULT, normalize_headers


class AsyncTransport(Transport):
    """
    Encapsulation of transport-related to logic. Handles instantiation of the
    individual nodes as well as creating a node pool to hold them.

    Main interface is the :meth:`elastic_transport.Transport.perform_request` method.
    """

    def __init__(
        self,
        node_configs: List[NodeConfig],
        node_class: Union[str, Type[BaseNode]] = AiohttpHttpNode,
        node_pool_class: Type[NodePool] = NodePool,
        randomize_nodes_in_pool: bool = True,
        node_selector_class: Optional[Union[str, Type[NodeSelector]]] = None,
        dead_backoff_factor: Optional[float] = None,
        max_dead_backoff: Optional[float] = None,
        serializers=None,
        max_retries: int = 3,
        retry_on_status=(429, 502, 503, 504),
        retry_on_timeout: bool = False,
        sniff_on_start: bool = False,
        sniff_before_requests: bool = False,
        sniff_on_node_failure: bool = False,
        sniff_timeout: Optional[float] = 1.0,
        min_delay_between_sniffing: float = 10.0,
        sniff_callback: Optional[
            Callable[
                ["Transport", "SniffOptions"],
                Union[List[NodeConfig], Awaitable[List[NodeConfig]]],
            ]
        ] = None,
    ):
        """
        :arg node_configs: List of 'NodeConfig' instances to create initial set of nodes.
        :arg node_class: subclass of :class:`~elastic_transport.BaseNode` to use
            or the name of the Connection (ie 'urllib3', 'requests')
        :arg node_pool_class: subclass of :class:`~elastic_transport.NodePool` to use
        :arg randomize_nodes_in_pool: Set to false to not randomize nodes within the pool.
            Defaults to true.
        :arg node_selector_class: Class to be used to select nodes within
            the :class:`~elastic_transport.NodePool`.
        :arg dead_backoff_factor: Exponential backoff factor to calculate the amount
            of time to timeout a node after an unsuccessful API call.
        :arg max_dead_backoff: Maximum amount of time to timeout a node after an
            unsuccessful API call.
        :arg serializers: optional dict of serializer instances that will be
            used for deserializing data coming from the server. (key is the mimetype)
        :arg max_retries: Maximum number of retries for an API call.
            Set to 0 to disable retries. Defaults to ``0``.
        :arg retry_on_status: set of HTTP status codes on which we should retry
            on a different node. defaults to ``(429, 502, 503, 504)``
        :arg retry_on_timeout: should timeout trigger a retry on different
            node? (default ``False``)
        :arg sniff_on_start: If ``True`` will sniff for additional nodes as soon
            as possible, guaranteed before the first request.
        :arg sniff_on_node_failure: If ``True`` will sniff for additional nodees
            after a node is marked as dead in the pool.
        :arg sniff_before_requests: If ``True`` will occasionally sniff for additional
            nodes as requests are sent.
        :arg sniff_timeout: Timeout value in seconds to use for sniffing requests.
            Defaults to 1 second.
        :arg min_delay_between_sniffing: Number of seconds to wait between calls to
            :meth:`elastic_transport.Transport.sniff` to avoid sniffing too frequently.
            Defaults to 10 seconds.
        :arg sniff_callback: Function that is passed a :class:`elastic_transport.Transport` and
            :class:`elastic_transport.SniffOptions` and should do node discovery and
            return a list of :class:`elastic_transport.NodeConfig` instances or a coroutine
            that returns the list.
        """

        # Since we don't pass all the sniffing options to super().__init__()
        # we want to validate the sniffing options here too.
        validate_sniffing_options(
            node_configs=node_configs,
            sniff_on_start=sniff_on_start,
            sniff_before_requests=sniff_before_requests,
            sniff_on_node_failure=sniff_on_node_failure,
            sniff_callback=sniff_callback,
        )

        super().__init__(
            node_configs=node_configs,
            node_class=node_class,
            node_pool_class=node_pool_class,
            randomize_nodes_in_pool=randomize_nodes_in_pool,
            node_selector_class=node_selector_class,
            dead_backoff_factor=dead_backoff_factor,
            max_dead_backoff=max_dead_backoff,
            serializers=serializers,
            max_retries=max_retries,
            retry_on_status=retry_on_status,
            retry_on_timeout=retry_on_timeout,
            sniff_timeout=sniff_timeout,
            min_delay_between_sniffing=min_delay_between_sniffing,
        )

        self._sniff_on_start = sniff_on_start
        self._sniff_before_requests = sniff_before_requests
        self._sniff_on_node_failure = sniff_on_node_failure
        self._sniff_timeout = sniff_timeout
        self._sniff_callback = sniff_callback
        self._sniffing_lock = None
        self._sniffing_task: Optional[asyncio.Task] = None
        self._last_sniffed_at = 0.0
        self._loop: Optional[asyncio.BaseEventLoop] = None

    async def perform_request(
        self,
        method: str,
        target: str,
        headers=None,
        body: Optional[Any] = None,
        request_timeout=DEFAULT,
        ignore_status=(),
    ) -> Tuple[ApiResponseMeta, Any]:
        """
        Perform the actual request. Retrieve a node from the node
        pool, pass all the information to it's perform_request method and
        return the data.

        If an exception was raised, mark the node as failed and retry (up
        to `max_retries` times).

        If the operation was successful and the node used was previously
        marked as dead, mark it as live, resetting it's failure count.

        :arg method: HTTP method to use
        :arg target: HTTP request target
        :arg headers: dictionary of headers, will be handed over to the
            underlying :class:`~elastic_transport.BaseNode` class
        :arg body: body of the request, will be serialized using serializer and
            passed to the node
        :arg request_timeout: Timeout to be passed to the HTTP client for the request
        :arg ignore_status: Collection of HTTP status codes to not raise an error for.
        :returns: Tuple of the HttpResponse with the deserialized response.
        """
        await self._async_init()

        if isinstance(ignore_status, int):
            ignore_status = {ignore_status}

        request_headers = normalize_headers(headers)

        # Serialize the request body to bytes based on the given mimetype.
        if body is not None:
            if "content-type" not in request_headers:
                raise ValueError(
                    "Must provide a 'Content-Type' header to requests with bodies"
                )
            mimetype = request_headers["content-type"].partition(";")[0] or None
            request_data = self.deserializer.dumps(body, mimetype=mimetype)
        else:
            request_data = None

        # Errors are stored from (oldest->newest)
        errors = []

        for attempt in range(self.max_retries + 1):

            # If we sniff before requests are made we want to do so before
            # 'node_pool.get()' is called so our sniffed nodes show up in the pool.
            if self._sniff_before_requests:
                await self.sniff(False)

            node = self.node_pool.get()
            try:
                response, raw_data = await node.perform_request(
                    method,
                    target,
                    body=request_data,
                    headers=request_headers,
                    ignore_status=ignore_status,
                    request_timeout=request_timeout,
                )

                if raw_data not in (None, b""):
                    data = self.deserializer.loads(raw_data, response.mimetype)
                else:
                    data = None

                # Non-2XX statuses should be re-raised as ApiErrors.
                if not (200 <= response.status <= 299):
                    raise HTTP_STATUS_TO_ERROR.get(response.status, ApiError)(
                        data, status=response.status
                    )

            except TransportError as e:
                retry = False
                node_failure = e.status not in NOT_DEAD_NODE_HTTP_STATUSES
                if isinstance(e, ConnectionTimeout):
                    retry = self.retry_on_timeout
                    node_failure = True
                elif isinstance(e, ConnectionError):
                    retry = True
                    node_failure = True
                elif e.status in self.retry_on_status:
                    retry = True

                # If the error was determined to be a node failure
                # we mark it dead in the node pool to allow for
                # other nodes to be retried.
                if node_failure:
                    self.node_pool.mark_dead(node)

                    if self._sniff_on_node_failure:
                        try:
                            await self.sniff(False)
                        except TransportError:
                            # If sniffing on failure, it could fail too. Catch the
                            # exception not to interrupt the retries.
                            pass

                if retry:
                    # raise exception on last retry
                    if attempt == self.max_retries:
                        e.errors = tuple(errors)
                        raise
                    else:
                        errors.append(e)
                else:
                    e.errors = tuple(errors)
                    raise

            else:
                # node didn't fail, confirm it's live status
                self.node_pool.mark_live(node)
                return response, data

    async def sniff(self, is_initial_sniff: bool) -> None:
        await self._async_init()
        task = self._create_sniffing_task(is_initial_sniff)

        # Only block on the task if this is the initial sniff.
        # Otherwise we do the sniffing in the background.
        if is_initial_sniff and task:
            await task

    async def close(self) -> None:
        """
        Explicitly closes all nodes in the transport's pool
        """
        for node in self.node_pool.all():
            await node.close()

    def _should_sniff(self, is_initial_sniff: bool) -> bool:
        """Decide if we should sniff or not. _async_init() must be called
        before using this function.The async implementation doesn't have a lock.
        """
        if is_initial_sniff:
            return True

        # Only start a new sniff if the previous run is completed.
        if self._sniffing_task:
            if not self._sniffing_task.done():
                return False
            # If there was a previous run we collect the sniffing task's
            # result as it could have failed with an exception.
            self._sniffing_task.result()

        return (
            self._loop.time() - self._last_sniffed_at
            >= self._min_delay_between_sniffing
        )

    def _create_sniffing_task(self, is_initial_sniff: bool) -> Optional[asyncio.Task]:
        """Creates a sniffing task if one should be created and returns the task if created."""
        task = None
        if self._should_sniff(is_initial_sniff):
            # 'self._sniffing_task' is unset within the task implementation.
            task = self._loop.create_task(self._sniffing_task_impl(is_initial_sniff))
            self._sniffing_task = task
        return task

    async def _sniffing_task_impl(self, is_initial_sniff: bool) -> None:
        """Implementation of the sniffing task"""
        previously_sniffed_at = self._last_sniffed_at
        try:
            self._last_sniffed_at = self._loop.time()
            options = SniffOptions(
                is_initial_sniff=is_initial_sniff, sniff_timeout=self._sniff_timeout
            )
            for node_config in await await_if_coro(self._sniff_callback(self, options)):
                self.node_pool.add(node_config)

        # If sniffing failed for any reason we
        # want to allow retrying immediately.
        except BaseException:
            self._last_sniffed_at = previously_sniffed_at
            raise

    async def _async_init(self) -> None:
        """Async constructor which is called on the first call to perform_request()
        because we're not guaranteed to be within an active asyncio event loop
        when __init__() is called.
        """
        if self._loop is not None:
            return  # Call at most once!
        self._loop = get_running_loop()
        if self._sniff_on_start:
            await self.sniff(True)
