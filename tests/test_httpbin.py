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

from elastic_transport import NotFoundError, QueryParams, Transport


@pytest.mark.parametrize("connection_class", ["urllib3", "requests"])
def test_simple_request(connection_class):
    t = Transport("https://httpbin.org", connection_class=connection_class)

    params = QueryParams()
    params.add("key[]", "1")
    params.add("key[]", "2")
    params.add("q1", None)
    params.add("q2", "")

    resp = t.perform_request(
        "GET",
        "/anything",
        headers={"Custom": "headeR"},
        params=params,
        body={"JSON": "body"},
    )
    assert resp.status == 200
    assert resp["method"] == "GET"
    assert resp["url"] == "https://httpbin.org/anything?key[]=1&key[]=2&q1&q2="

    # httpbin makes no-value query params into ''
    assert resp["args"] == {
        "key[]": ["1", "2"],
        "q1": "",
        "q2": "",
    }
    assert resp["data"] == '{"JSON":"body"}'
    assert resp["json"] == {"JSON": "body"}

    request_headers = {
        "Content-Type": "application/json",
        "Content-Length": "15",
        "Custom": "headeR",
        "Host": "httpbin.org",
    }
    assert all(v == resp["headers"][k] for k, v in request_headers.items())

    assert resp.headers["content-type"] == "application/json"
    assert resp.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize("connection_class", ["urllib3", "requests"])
@pytest.mark.parametrize("status", [200, 404])
def test_head_request(connection_class, status):
    t = Transport("https://httpbin.org", connection_class=connection_class)
    resp = t.perform_request(
        "HEAD",
        "/status/%d" % status,
        headers={"Custom": "headeR"},
        params={"Query": "String"},
        body={"JSON": "body"},
    )
    assert resp.status == status
    assert bool(resp) is (status == 200)


@pytest.mark.parametrize("connection_class", ["urllib3", "requests"])
def test_get_404_request(connection_class):
    t = Transport("https://httpbin.org", connection_class=connection_class)
    with pytest.raises(NotFoundError) as e:
        t.perform_request(
            "GET",
            "/status/404",
            headers={"Custom": "headeR"},
            params={"Query": "String"},
            body={"JSON": "body"},
        )

    resp = e.value
    assert resp.status == 404
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    assert resp.headers["Content-Type"] == "text/html; charset=utf-8"
