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

from typing import Any, List, Optional, Tuple, Type, Union

from ._exceptions import (
    HTTP_STATUS_TO_ERROR,
    ApiError,
    ConnectionError,
    ConnectionTimeout,
    TransportError,
)
from ._models import ApiResponseMeta, NodeConfig
from ._node import AiohttpHttpNode, BaseNode
from ._node_pool import NodePool, NodeSelector
from ._transport import NOT_DEAD_NODE_HTTP_STATUSES, Transport
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

        Any extra keyword arguments will be passed to the `node_class`
        when creating and instance unless overridden by that node's
        options provided as part of the hosts parameter.
        """
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
        )

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
                if isinstance(e, ConnectionTimeout):
                    retry = self.retry_on_timeout
                elif isinstance(e, ConnectionError):
                    retry = True
                elif e.status in self.retry_on_status:
                    retry = True

                if retry:
                    try:
                        # only mark as dead if we are retrying
                        if e.status not in NOT_DEAD_NODE_HTTP_STATUSES:
                            await self.mark_dead(node)
                    except TransportError:
                        # If sniffing on failure, it could fail too. Catch the
                        # exception not to interrupt the retries.
                        pass
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

    async def mark_dead(self, node: BaseNode) -> None:
        """Marks a node as dead and optionally starts sniffing for additional nodes if enabled"""
        self.node_pool.mark_dead(node)

    async def close(self) -> None:
        """
        Explicitly closes all nodes in the transport's pool
        """
        for node in self.node_pool.all():
            await node.close()
