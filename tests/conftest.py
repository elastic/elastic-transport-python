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

import hashlib
import socket
import ssl

import pytest

from elastic_transport import BaseNode, HttpHeaders, HttpResponse


class DummyNode(BaseNode):
    def __init__(self, **kwargs):
        self.exception = kwargs.pop("exception", None)
        self.status = kwargs.pop("status", 200)
        self.body = kwargs.pop("body", b"{}")
        self.calls = []
        super().__init__(**kwargs)
        self.headers = kwargs.pop("headers", {})

    def perform_request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        response = HttpResponse(
            duration=0.0,
            version="1.1",
            status=self.status,
            headers=HttpHeaders(self.headers),
        )
        return response, self.body


@pytest.fixture(scope="session")
def httpbin_cert_fingerprint() -> bytes:
    """Gets the SHA256 fingerprint of the certificate for 'httpbin.org'"""
    sock = socket.create_connection(("httpbin.org", 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock)
    digest = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
    assert len(digest) == 64
    sock.close()
    return digest
