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


class Request(object):
    """HTTP request"""

    __slots__ = ("method", "path", "headers", "params")

    def __init__(self, method, path, headers, params):
        self.method = method
        self.path = path
        self.headers = headers
        self.params = params

    def __eq__(self, other):
        if isinstance(other, Request):
            return (
                self.method == other.method
                and self.path == other.path
                and self.headers == other.headers
                and self.params == other.params
            )
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Request):
            return (
                self.method != other.method
                or self.path != other.path
                or self.headers != other.headers
                or self.params != other.params
            )
        return NotImplemented


class Response(object):
    """HTTP response"""

    __slots__ = ("request", "headers", "status", "body")

    def __init__(self, request, headers, status, body):
        self.request = request
        self.headers = headers
        self.status = status
        self.body = body

    def __repr__(self):
        return repr(self.body)

    def __str__(self):
        return str(self.body)

    def __getattr__(self, item):
        return getattr(self.body, item)

    def __getitem__(self, item):
        return self.body[item]

    def __bool__(self):
        return bool(self.body)

    # Python 2 compatibility
    __nonzero__ = __bool__

    def __iter__(self):
        return iter(self.body)

    def __contains__(self, item):
        return item in self.body

    def __len__(self):
        return len(self.body)

    def __eq__(self, other):
        if isinstance(other, type(self.body)):
            return other == self.body
        elif isinstance(other, Response):
            return other.body == self.body
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, type(self.body)):
            return other != self.body
        elif isinstance(other, Response):
            return other.body != self.body
        return NotImplemented
