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

from .compat import string_types, urlparse
from .connection import RequestsHttpConnection, Urllib3HttpConnection
from .connection_pool import ConnectionPool, DummyConnectionPool, EmptyConnectionPool
from .exceptions import ConnectionError, ConnectionTimeout, TransportError
from .response import DictResponse, ListResponse, Response
from .serializer import DEFAULT_SERIALIZERS, Deserializer
from .utils import DEFAULT, normalize_headers

# Allows for using a connection_class by name rather than import.
CONNECTION_CLASS_NAMES = {
    "urllib3": Urllib3HttpConnection,
    "requests": RequestsHttpConnection,
}


class Transport(object):
    """
    Encapsulation of transport-related to logic. Handles instantiation of the
    individual connections as well as creating a connection pool to hold them.

    Main interface is the `perform_request` method.
    """

    DEFAULT_CONNECTION_CLASS = Urllib3HttpConnection

    def __init__(
        self,
        hosts=None,
        connection_class=None,
        connection_pool_class=ConnectionPool,
        serializers=None,
        default_mimetype="application/json",
        default_hosts=None,
        max_retries=3,
        retry_on_status=(502, 503, 504),
        retry_on_timeout=False,
        **kwargs
    ):
        """
        :arg hosts: list of dictionaries, each containing keyword arguments to
            create a `connection_class` instance
        :arg connection_class: subclass of :class:`~elastic_transport.Connection` to use
            or the name of the Connection (ie 'urllib3', 'requests')
        :arg connection_pool_class: subclass of :class:`~elastic_transport.ConnectionPool` to use
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

        Any extra keyword arguments will be passed to the `connection_class`
        when creating and instance unless overridden by that connection's
        options provided as part of the hosts parameter.
        """
        hosts = _normalize_hosts(hosts, default_hosts)
        if connection_class is None:
            connection_class = self.DEFAULT_CONNECTION_CLASS
        elif isinstance(connection_class, str):
            if connection_class not in CONNECTION_CLASS_NAMES:
                raise ValueError(
                    "Unknown option for connection_class: '%s'. "
                    "Available options are: '%s'"
                    % (
                        connection_class,
                        "', '".join(sorted(CONNECTION_CLASS_NAMES.keys())),
                    )
                )
            connection_class = CONNECTION_CLASS_NAMES[connection_class]

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

        # data serializer
        self.serializer = _serializers[default_mimetype]

        # store all strategies...
        self.connection_pool_class = connection_pool_class
        self.connection_class = connection_class

        # ...save kwargs to be passed to the connections
        self.kwargs = kwargs
        self.hosts = hosts

        # Start with an empty pool specifically for `AsyncTransport`.
        # It should never be used, will be replaced on first call to
        # .set_connections()
        self.connection_pool = EmptyConnectionPool()

        if hosts:
            # ...and instantiate them
            self.set_connections(hosts)
            # retain the original connection instances for sniffing
            self.seed_connections = list(self.connection_pool.connections[:])
        else:
            self.seed_connections = []

    def add_connection(self, host):
        """
        Create a new :class:`~elastic_enterprise_search.Connection` instance and add it to the pool.

        :arg host: kwargs that will be used to create the instance
        """
        self.hosts.append(host)
        self.set_connections(self.hosts)

    def set_connections(self, hosts):
        """
        Instantiate all the connections and create new connection pool to hold them.
        Tries to identify unchanged hosts and re-use existing
        :class:`~elastic_transport.Connection` instances.

        :arg hosts: same as `__init__`
        """
        # construct the connections
        def _create_connection(host):
            # if this is not the initial setup look at the existing connection
            # options and identify connections that haven't changed and can be
            # kept around.
            if hasattr(self, "connection_pool"):
                for (connection, old_host) in self.connection_pool.connection_opts:
                    if old_host == host:
                        return connection

            # previously unseen params, create new connection
            kwargs = self.kwargs.copy()
            kwargs.update(host)
            return self.connection_class(**kwargs)

        connections = map(_create_connection, hosts)

        connections = list(zip(connections, hosts))
        if len(connections) == 1:
            self.connection_pool = DummyConnectionPool(connections)
        else:
            # pass the hosts dicts to the connection pool to optionally extract parameters from
            self.connection_pool = self.connection_pool_class(
                connections, **self.kwargs
            )

    def get_connection(self):
        """
        Retrieve a :class:`~elastic_transport.Connection` instance from the
        :class:`~elastic_transport.ConnectionPool` instance.
        """
        return self.connection_pool.get_connection()

    def mark_dead(self, connection):
        """
        Mark a connection as dead (failed) in the connection pool. If sniffing
        on failure is enabled this will initiate the sniffing process.

        :arg connection: instance of :class:`~elastic_transport.Connection` that failed
        """
        # mark as dead even when sniffing to avoid hitting this host during the sniff process
        self.connection_pool.mark_dead(connection)

    def perform_request(
        self,
        method,
        path,
        headers=None,
        params=None,
        body=None,
        request_timeout=DEFAULT,
        ignore_status=(),
    ):
        """
        Perform the actual request. Retrieve a connection from the connection
        pool, pass all the information to it's perform_request method and
        return the data.

        If an exception was raised, mark the connection as failed and retry (up
        to `max_retries` times).

        If the operation was successful and the connection used was previously
        marked as dead, mark it as live, resetting it's failure count.

        :arg method: HTTP method to use
        :arg path: relative URL to target
        :arg headers: dictionary of headers, will be handed over to the
            underlying :class:`~elastic_transport.Connection` class
        :arg params: dictionary of query parameters, will be handed over to the
            underlying :class:`~elastic_transport.Connection` class for serialization
        :arg body: body of the request, will be serialized using serializer and
            passed to the connection
        :arg request_timeout: Timeout to be passed to the HTTP client for the request
        :arg ignore_status: Collection of HTTP status codes to not raise an error for.
        :returns: Deserialized Response
        """
        if isinstance(ignore_status, int):
            ignore_status = (ignore_status,)

        if body is not None:
            body = self.serializer.dumps(body)

        if body is not None:
            try:
                body = body.encode("utf-8", "surrogatepass")
            except (UnicodeError, AttributeError):
                # bytes/str - no need to re-encode
                pass

        headers = normalize_headers(headers)

        # Errors are stored from (oldest->newest)
        errors = []

        for attempt in range(self.max_retries + 1):
            connection = self.get_connection()

            try:
                status, headers_response, data = connection.perform_request(
                    method,
                    path,
                    params,
                    body,
                    headers=headers,
                    ignore_status=ignore_status,
                    request_timeout=request_timeout,
                )
            except TransportError as e:
                if method == "HEAD" and e.status == 404:
                    return Response(
                        status=404,
                        headers={},
                        body=False,
                    )

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
                        self.mark_dead(connection)
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
                # connection didn't fail, confirm it's live status
                self.connection_pool.mark_live(connection)

                if method == "HEAD":
                    return Response(
                        status=status,
                        headers=headers_response,
                        body=200 <= status < 300,
                    )

                if data:
                    data = self.deserializer.loads(
                        data, headers_response.get("content-type")
                    )

                # After the body is deserialized put the data
                # into one of the typed responses
                response_cls = Response
                if isinstance(data, list):
                    response_cls = ListResponse
                elif isinstance(data, dict):
                    response_cls = DictResponse
                return response_cls(
                    status=status,
                    headers=headers_response,
                    body=data,
                )

    def close(self):
        """
        Explicitly closes connections
        """
        self.connection_pool.close()


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
