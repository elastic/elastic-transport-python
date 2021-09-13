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

from typing import Optional


class TransportError(Exception):
    """Generic exception for the 'elastic-transport' package.

    For the 'errors' attribute, errors are ordered from
    most recently raised (index=0) to least recently raised (index=N)

    If an HTTP status code is available with the error it
    will be stored under 'status'. If HTTP headers are available
    they are stored under 'headers'.
    """

    status: Optional[int] = None

    def __init__(self, message, errors=(), status=None):
        super().__init__(message)
        self.errors = tuple(errors)
        self.message = message
        self.status = status

    def __repr__(self):
        parts = [repr(self.message)]
        if self.status is not None:
            parts.append(f"status={self.status!r}")
        if self.errors:
            parts.append(f"errors={self.errors!r}")
        return "{}({})".format(self.__class__.__name__, ", ".join(parts))

    def __str__(self) -> str:
        return str(self.message)


class SerializationError(TransportError):
    """Error that occurred during the serialization or
    deserialization of an HTTP message body
    """


class ConnectionError(TransportError):
    """Error raised by the HTTP connection"""


class ConnectionTimeout(TransportError):
    """Connection timed out during an operation"""


class ApiError(TransportError):
    """Error that is raised by the service or API"""

    def __init__(self, message, errors=(), status=None):
        if status is None:
            status = getattr(self, "status", None)
        super().__init__(message=message, errors=errors, status=status)


class BadRequestError(ApiError):
    """Error for HTTP status 400 'Bad Request'"""

    status = 400


class UnauthorizedError(ApiError):
    """Error for HTTP status 401 'Unauthorized'"""

    status = 401


class PaymentRequiredError(ApiError):
    """Error for HTTP status 402 'Payment Required'
    Usually signals that your instance doesn't have
    a proper license active for the operation
    """

    status = 402


class ForbiddenError(ApiError):
    """Error for HTTP status 403 'Forbidden'"""

    status = 403


class NotFoundError(ApiError):
    """Error for HTTP status 404 'Not Found'"""

    status = 404


class ConflictError(ApiError):
    """Error for HTTP status 409 'Conflict'"""

    status = 409


class PayloadTooLargeError(ApiError):
    """Error for HTTP status 413 'Payload Too Large'"""

    status = 413


class UnprocessableEntityError(ApiError):
    """Error for HTTP status 422 'Unprocessable Entity'"""

    status = 422


class TooManyRequestsError(ApiError):
    """Error for HTTP status 429 'Too Many Requests'"""

    status = 429


class InternalServerError(ApiError):
    """Error for HTTP status 500 'Internal Server Error'"""

    status = 500


class MethodNotImplementedError(ApiError):
    """Error for HTTP status 501 'Method Not Allowed'"""

    status = 501


class BadGatewayError(ApiError):
    """Error for HTTP status 502 'Bad Gateway'"""

    status = 502


class ServiceUnavailableError(ApiError):
    """Error for HTTP status 503 'Service Unavailable'"""

    status = 503


class GatewayTimeoutError(ApiError):
    """Error for HTTP status 504 'Gateway Timeout'"""

    status = 504


HTTP_STATUS_TO_ERROR = {
    400: BadRequestError,
    401: UnauthorizedError,
    402: PaymentRequiredError,
    403: ForbiddenError,
    404: NotFoundError,
    405: MethodNotImplementedError,
    409: ConflictError,
    413: PayloadTooLargeError,
    422: UnprocessableEntityError,
    429: TooManyRequestsError,
    500: InternalServerError,
    502: BadGatewayError,
    503: ServiceUnavailableError,
    504: GatewayTimeoutError,
}
