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

import pytest

from elastic_transport._utils import is_ipaddress


@pytest.mark.parametrize(
    "addr",
    [
        # IPv6
        "::1",
        "::",
        "FE80::8939:7684:D84b:a5A4%251",
        # IPv4
        "127.0.0.1",
        "8.8.8.8",
        b"127.0.0.1",
        # IPv6 w/ Zone IDs
        "FE80::8939:7684:D84b:a5A4%251",
        b"FE80::8939:7684:D84b:a5A4%251",
        "FE80::8939:7684:D84b:a5A4%19",
        b"FE80::8939:7684:D84b:a5A4%19",
    ],
)
def test_is_ipaddress(addr):
    assert is_ipaddress(addr)


@pytest.mark.parametrize(
    "addr",
    [
        "www.python.org",
        b"www.python.org",
        "v2.sg.media-imdb.com",
        b"v2.sg.media-imdb.com",
    ],
)
def test_is_not_ipaddress(addr):
    assert not is_ipaddress(addr)
