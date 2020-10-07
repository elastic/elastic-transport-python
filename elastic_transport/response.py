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


class Response(object):
    """HTTP response"""

    def __init__(self, headers, status, body):
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


class DictResponse(Response, dict):
    def __init__(self, headers, status, body):
        Response.__init__(self, headers, status, body)
        dict.__init__(self, body)


class ListResponse(Response, list):
    def __init__(self, headers, status, body):
        Response.__init__(self, headers, status, body)
        list.__init__(self, body)
