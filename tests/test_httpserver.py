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

import warnings

import pytest

from elastic_transport import Transport


@pytest.mark.parametrize("node_class", ["urllib3", "requests"])
def test_simple_request(node_class, https_server_ip_node_config):
    with warnings.catch_warnings():
        warnings.simplefilter("error")

        t = Transport([https_server_ip_node_config], node_class=node_class)

        resp, data = t.perform_request("GET", "/foobar")
        assert resp.status == 200
        assert data == {"foo": "bar"}
