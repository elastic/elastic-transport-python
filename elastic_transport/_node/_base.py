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
import logging
from typing import Tuple

from .._models import HttpHeaders, HttpResponse, NodeConfig
from .._version import __version__
from ..client_utils import DEFAULT

logger = logging.getLogger("elastic_transport.node")

DEFAULT_CA_CERTS = None
DEFAULT_USER_AGENT = f"elastic-transport-python/{__version__}"
RERAISE_EXCEPTIONS = (RecursionError, asyncio.CancelledError)

try:
    import certifi

    DEFAULT_CA_CERTS = certifi.where()
except ImportError:  # pragma: nocover
    pass


class BaseNode:
    """
    Class responsible for maintaining a connection to a node. It
    holds persistent node pool to it and it's main interface
    (``perform_request``) is thread-safe.

    :arg config: :class:`~elastic_transport.NodeConfig` instance
    """

    _ELASTIC_CLIENT_META = None

    def __init__(self, config: NodeConfig):
        self._config = config
        self._headers = self.config.headers.copy()
        self.headers.setdefault("connection", "keep-alive")
        self.headers.setdefault("user-agent", DEFAULT_USER_AGENT)

        self._http_compress = bool(config.http_compress or False)
        if config.http_compress:
            self.headers["accept-encoding"] = "gzip"

        self._scheme = config.scheme
        self._host = config.host
        self._port = config.port
        self._path_prefix = (
            ("/" + config.path_prefix.strip("/")) if config.path_prefix else ""
        )

    @property
    def config(self) -> NodeConfig:
        return self._config

    @property
    def headers(self) -> HttpHeaders:
        return self._headers

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def path_prefix(self) -> str:
        return self._path_prefix

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.base_url}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseNode):
            raise TypeError(f"Unsupported equality check for {self} and {other}")
        return self.__hash__() == other.__hash__()

    def __hash__(self) -> int:
        return hash(id(self))

    @property
    def base_url(self) -> str:
        return "".join(
            [
                self.scheme,
                "://",
                # IPv6 must be wrapped by [...]
                "[%s]" % self.host if ":" in self.host else self.host,
                ":%s" % self.port if self.port is not None else "",
                self.path_prefix,
            ]
        )

    def perform_request(
        self,
        method,
        target,
        body=None,
        request_timeout=DEFAULT,
        ignore_status=(),
        headers=None,
    ) -> Tuple[HttpResponse, bytes]:  # pragma: nocover
        raise NotImplementedError()

    def close(self) -> None:  # pragma: nocover
        pass

    def log_request_success(self, method, url, body, status, response, duration):
        """Log a successful API call"""
        # body has already been serialized to utf-8, deserialize it for logging
        # TODO: find a better way to avoid (de)encoding the body back and forth
        if body:
            try:
                body = body.decode("utf-8", "ignore")
            except AttributeError:
                pass

        logger.info("%s %s [status:%s request:%.3fs]", method, url, status, duration)
        logger.debug("> %s", body)
        logger.debug("< %s", response)

    def log_request_fail(
        self,
        method,
        url,
        body,
        duration,
        status=None,
        response=None,
        exception=None,
    ):
        """Log an unsuccessful API call"""
        # do not log 404s on HEAD requests
        if method == "HEAD" and status == 404:
            return
        logger.warning(
            "%s %s [status:%s request:%.3fs]",
            method,
            url,
            status or "N/A",
            duration,
            exc_info=exception is not None,
        )

        # body has already been serialized to utf-8, deserialize it for logging
        # TODO: find a better way to avoid (de)encoding the body back and forth
        if body:
            try:
                body = body.decode("utf-8", "ignore")
            except AttributeError:
                pass

        logger.debug("> %s", body)

        if response is not None:
            logger.debug("< %s", response)
