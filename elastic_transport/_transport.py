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

from platform import python_version
from typing import Dict, List, Type, Union

from ._compat import string_types, urlparse
from ._exceptions import (
    HTTP_STATUS_TO_ERROR,
    ApiError,
    ConnectionError,
    ConnectionTimeout,
    TransportError,
)
from ._models import NodeConfig
from ._node import AiohttpHttpNode, BaseNode, RequestsHttpNode, Urllib3HttpNode
from ._node_pool import NodePool
from ._serializer import DEFAULT_SERIALIZERS, Deserializer
from ._version import __version__
from .client_utils import DEFAULT, client_meta_version, normalize_headers

# Allows for using a node_class by name rather than import.
_NODE_CLASS_NAMES: Dict[str, Type[BaseNode]] = {
    "urllib3": Urllib3HttpNode,
    "requests": RequestsHttpNode,
    "aiohttp": AiohttpHttpNode,
}
# These are HTTP status errors that shouldn't be considered
# 'errors' for marking a node as dead. These errors typically
# mean everything is fine server-wise and instead the API call
# in question responded successfully.
_NOT_DEAD_NODE_HTTP_STATUSES = {400, 401, 403, 404}


class Transport:
    """
    Encapsulation of transport-related to logic. Handles instantiation of the
    individual nodes as well as creating a node pool to hold them.

    Main interface is the `perform_request` method.
    """

    def __init__(
        self,
        node_configs: List[NodeConfig],
        node_class: Union[str, Type[BaseNode]] = Urllib3HttpNode,
        node_pool_class: Type[NodePool] = NodePool,
        serializers=None,
        default_mimetype="application/json",
        default_hosts=None,
        max_retries=3,
        retry_on_status=(502, 503, 504),
        retry_on_timeout=False,
        **kwargs,
    ):
        """
        :arg node_configs: List of 'NodeConfig' instances to create initial set of nodes.
        :arg node_class: subclass of :class:`~elastic_transport.BaseNode` to use
            or the name of the Connection (ie 'urllib3', 'requests')
        :arg node_pool_class: subclass of :class:`~elastic_transport.NodePool` to use
        :arg serializers: optional dict of serializer instances that will be
            used for deserializing data coming from the server. (key is the mimetype)
        :arg default_mimetype: when no mimetype is specified by the server
            response assume this mimetype, defaults to `'application/json'`
        :arg default_hosts: Default hosts config to use if none is given.
        :arg max_retries: maximum number of retries before an exception is propagated
        :arg retry_on_status: set of HTTP status codes on which we should retry
            on a different node. defaults to ``(502, 503, 504)``
        :arg retry_on_timeout: should timeout trigger a retry on different
            node? (default ``False``)

        Any extra keyword arguments will be passed to the `node_class`
        when creating and instance unless overridden by that node's
        options provided as part of the hosts parameter.
        """
        if isinstance(node_class, str):
            if node_class not in _NODE_CLASS_NAMES:
                options = "', '".join(sorted(_NODE_CLASS_NAMES.keys()))
                raise ValueError(
                    f"Unknown option for node_class: '{node_class}'. "
                    f"Available options are: '{options}'"
                )
            node_class = _NODE_CLASS_NAMES[node_class]

        # Create the default metadata for the x-elastic-client-meta
        # HTTP header. Only requires adding the (service, service_version)
        # tuple to the beginning of the client_meta
        self._transport_client_meta = (
            ("py", client_meta_version(python_version())),
            ("t", client_meta_version(__version__)),
        )

        # Grab the 'HTTP_CLIENT_META' property from the node class
        http_client_meta = getattr(node_class, "_ELASTIC_CLIENT_META", None)
        if http_client_meta:
            self._transport_client_meta += (http_client_meta,)

        # serialization config
        _serializers = DEFAULT_SERIALIZERS.copy()
        # if custom serializers map has been supplied, override the defaults with it
        if serializers:
            _serializers.update(serializers)
        # create a deserializer with our config
        self.deserializer = Deserializer(_serializers, default_mimetype)

        self.max_retries = max_retries
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_status = retry_on_status

        # store all strategies...
        self.node_pool = node_pool_class(node_configs, node_class=node_class)

    def perform_request(
        self,
        method,
        target,
        headers=None,
        body=None,
        request_timeout=DEFAULT,
        ignore_status=(),
    ):
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
            # The body is already encoded to bytes
            # so we forward the request body along.
            if isinstance(body, bytes):
                request_data = body
            else:
                mimetype = (
                    request_headers.get("content-type", "").partition(";")[0] or None
                )
                request_data = self.deserializer.dumps(body, mimetype=mimetype)
        else:
            request_data = None

        # Errors are stored from (oldest->newest)
        errors = []

        for attempt in range(self.max_retries + 1):
            node = self.node_pool.get()

            try:
                response, raw_data = node.perform_request(
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
                        self.node_pool.mark_dead(node)
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

    def close(self) -> None:
        """
        Explicitly closes all nodes in the transport's pool
        """
        for node in self.node_pool.all():
            node.close()


def _normalize_hosts(hosts, default_hosts):
    # if hosts are empty, just defer to defaults
    if hosts is None:
        return default_hosts or [{}]

    # passed in just one string
    if isinstance(hosts, string_types):
        hosts = [hosts]

    out = []
    # normalize hosts to dicts
    for host in hosts:
        if isinstance(host, string_types):
            if "://" not in host:
                host = "//%s" % host

            parsed_url = urlparse(host)
            h = {"host": parsed_url.hostname}

            if parsed_url.port is not None:
                h["port"] = parsed_url.port

            if parsed_url.scheme == "https":
                h["port"] = parsed_url.port if parsed_url.port is not None else 443
                h["use_ssl"] = True

            if parsed_url.path and parsed_url.path != "/":
                h["url_prefix"] = parsed_url.path

            out.append(h)
        else:
            out.append(host)
    return out
