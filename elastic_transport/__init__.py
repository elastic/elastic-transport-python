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

"""Transport classes and utilities shared among Python Elastic client libraries"""

from ._version import __version__  # noqa
from .transport import Transport, Response
from .connection import Connection, Urllib3HttpConnection, RequestsHttpConnection
from .connection_pool import (
    ConnectionPool,
    DummyConnectionPool,
    EmptyConnectionPool,
    ConnectionSelector,
    RandomSelector,
    RoundRobinSelector,
)
from .exceptions import (
    TransportError,
    SerializationError,
    ConnectionError,
    ConnectionTimeout,
    APIError,
    BadGatewayError,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    InternalServerError,
    GatewayTimeoutError,
    MethodNotImplementedError,
    PayloadTooLargeError,
    PaymentRequiredError,
    ServiceUnavailableError,
    UnauthorizedError,
    UnprocessableEntityError,
    RetriesExhausted,
)
from .serializer import Serializer, JSONSerializer, TextSerializer, Deserializer

__all__ = [
    "APIError",
    "BadGatewayError",
    "BadRequestError",
    "ConflictError",
    "Connection",
    "ConnectionError",
    "ConnectionPool",
    "ConnectionSelector",
    "ConnectionTimeout",
    "Deserializer",
    "DummyConnectionPool",
    "EmptyConnectionPool",
    "ForbiddenError",
    "GatewayTimeoutError",
    "InternalServerError",
    "JSONSerializer",
    "MethodNotImplementedError",
    "NotFoundError",
    "PayloadTooLargeError",
    "PaymentRequiredError",
    "RandomSelector",
    "RequestsHttpConnection",
    "Response",
    "RetriesExhausted",
    "RoundRobinSelector",
    "SerializationError",
    "Serializer",
    "ServiceUnavailableError",
    "TextSerializer",
    "Transport",
    "TransportError",
    "UnauthorizedError",
    "UnprocessableEntityError",
    "Urllib3HttpConnection",
]
