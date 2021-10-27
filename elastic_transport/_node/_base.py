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
import os
import ssl
from typing import ClassVar, Optional, Tuple, Union

from .._models import ApiResponseMeta, HttpHeaders, NodeConfig
from .._version import __version__
from ..client_utils import DEFAULT, DefaultType

logger = logging.getLogger("elastic_transport.node")

DEFAULT_CA_CERTS: Optional[str] = None
DEFAULT_USER_AGENT = f"elastic-transport-python/{__version__}"
RERAISE_EXCEPTIONS = (RecursionError, asyncio.CancelledError)
BUILTIN_EXCEPTIONS = (
    ValueError,
    KeyError,
    NameError,
    AttributeError,
    LookupError,
    AssertionError,
    IndexError,
    MemoryError,
    RuntimeError,
    SystemError,
    TypeError,
)

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

    _CLIENT_META_HTTP_CLIENT: ClassVar[Tuple[str, str]]

    def __init__(self, config: NodeConfig):
        self._config = config
        self._headers: HttpHeaders = self.config.headers.copy()  # type: ignore[attr-defined]
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
        return f"<{self.__class__.__name__}({self.base_url})>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseNode):
            return NotImplemented
        return self.__hash__() == other.__hash__()

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, BaseNode):
            return NotImplemented
        return not self == other

    def __hash__(self) -> int:
        return hash((str(type(self).__name__), self.config))

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
        method: str,
        target: str,
        body: Optional[bytes] = None,
        headers: Optional[HttpHeaders] = None,
        request_timeout: Union[DefaultType, Optional[float]] = DEFAULT,
    ) -> Tuple[ApiResponseMeta, bytes]:  # pragma: nocover
        raise NotImplementedError()

    def close(self) -> None:  # pragma: nocover
        pass

    def log_request_success(self, method, url, body, status, response, duration):  # type: ignore
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

    def log_request_fail(  # type: ignore
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


_HAS_TLS_VERSION = hasattr(ssl, "TLSVersion")
_SSL_PROTOCOL_VERSION_ATTRS = ("TLSv1", "TLSv1_1", "TLSv1_2")
_SSL_PROTOCOL_VERSION_DEFAULT = getattr(ssl, "OP_NO_SSLv2", 0) | getattr(
    ssl, "OP_NO_SSLv3", 0
)
_SSL_PROTOCOL_VERSION_TO_OPTIONS = {}
_SSL_PROTOCOL_VERSION_TO_TLS_VERSION = {}
for i, _protocol_attr in enumerate(_SSL_PROTOCOL_VERSION_ATTRS):
    try:
        _protocol_value = getattr(ssl, f"PROTOCOL_{_protocol_attr}")
    except AttributeError:
        continue

    if _HAS_TLS_VERSION:
        _tls_version_value = getattr(ssl.TLSVersion, _protocol_attr)
        _SSL_PROTOCOL_VERSION_TO_TLS_VERSION[_protocol_value] = _tls_version_value
        _SSL_PROTOCOL_VERSION_TO_TLS_VERSION[_tls_version_value] = _tls_version_value

    # Because we're setting a minimum version we binary OR all the options together.
    _SSL_PROTOCOL_VERSION_TO_OPTIONS[
        _protocol_value
    ] = _SSL_PROTOCOL_VERSION_DEFAULT | sum(
        getattr(ssl, f"OP_NO_{_attr}", 0) for _attr in _SSL_PROTOCOL_VERSION_ATTRS[:i]
    )

# TLSv1.3 is unique, doesn't have a PROTOCOL_TLSvX counterpart. So we have to set it manually.
if _HAS_TLS_VERSION:
    try:
        _SSL_PROTOCOL_VERSION_TO_TLS_VERSION[
            ssl.TLSVersion.TLSv1_3
        ] = ssl.TLSVersion.TLSv1_3
    except AttributeError:  # pragma: nocover
        pass


def ssl_context_from_node_config(node_config: NodeConfig) -> ssl.SSLContext:
    if node_config.ssl_context:
        ctx = node_config.ssl_context
    else:
        ctx = ssl.create_default_context()

        # Enable/disable certificate verification in these orders
        # to avoid 'ValueErrors' from SSLContext. We only do this
        # step if the user doesn't pass a preconfigured SSLContext.
        if node_config.verify_certs:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    # Enable logging of TLS session keys for use with Wireshark.
    if hasattr(ctx, "keylog_filename"):
        sslkeylogfile = os.environ.get("SSLKEYLOGFILE", "")
        if sslkeylogfile:
            ctx.keylog_filename = sslkeylogfile  # type: ignore[attr-defined]

    # Apply the 'ssl_version' if given, otherwise default to TLSv1.2+
    ssl_version = node_config.ssl_version
    if ssl_version is None:
        if _HAS_TLS_VERSION:
            ssl_version = ssl.TLSVersion.TLSv1_2
        else:
            ssl_version = ssl.PROTOCOL_TLSv1_2

    try:
        if _HAS_TLS_VERSION:
            ctx.minimum_version = _SSL_PROTOCOL_VERSION_TO_TLS_VERSION[ssl_version]
        else:
            ctx.options |= _SSL_PROTOCOL_VERSION_TO_OPTIONS[ssl_version]
    except KeyError:
        raise ValueError(
            f"Unsupported value for 'ssl_version': {ssl_version!r}. Must be "
            "either 'ssl.PROTOCOL_TLSvX' or 'ssl.TLSVersion.TLSvX'"
        ) from None

    return ctx
