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

from elastic_transport import (
    ApiError,
    InternalServerError,
    NotFoundError,
    QueryParams,
    Transport,
)


@pytest.mark.parametrize("node_class", ["urllib3", "requests"])
def test_simple_request(node_class):
    t = Transport("https://httpbin.org", node_class=node_class)

    params = QueryParams()
    params.add("key[]", "1")
    params.add("key[]", "2")
    params.add("q1", None)
    params.add("q2", "")

    resp, data = t.perform_request(
        "GET",
        "/anything",
        headers={"Custom": "headeR"},
        params=params,
        body={"JSON": "body"},
    )
    assert resp.status == 200
    assert data["method"] == "GET"
    assert data["url"] == "https://httpbin.org/anything?key[]=1&key[]=2&q1&q2="

    # httpbin makes no-value query params into ''
    assert data["args"] == {
        "key[]": ["1", "2"],
        "q1": "",
        "q2": "",
    }
    assert data["data"] == '{"JSON":"body"}'
    assert data["json"] == {"JSON": "body"}

    request_headers = {
        "Content-Type": "application/json",
        "Content-Length": "15",
        "Custom": "headeR",
        "Host": "httpbin.org",
    }
    assert all(v == data["headers"][k] for k, v in request_headers.items())

    assert resp.headers["content-type"] == "application/json"
    assert resp.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize("node_class", ["urllib3", "requests"])
def test_head_request_200(node_class):
    t = Transport("https://httpbin.org", node_class=node_class)
    resp, data = t.perform_request(
        "HEAD",
        "/status/200",
        headers={"Custom": "headeR"},
        params={"Query": "String"},
        body={"JSON": "body"},
    )
    assert resp.status == 200
    assert data is None


@pytest.mark.parametrize("node_class", ["urllib3", "requests"])
@pytest.mark.parametrize("status", [404, 500])
def test_head_request_error(node_class, status):
    t = Transport("https://httpbin.org", node_class=node_class)
    with pytest.raises(ApiError) as e:
        t.perform_request(
            "HEAD",
            f"/status/{status}",
            headers={"Custom": "headeR"},
            params={"Query": "String"},
            body={"JSON": "body"},
        )

    assert e.value.status == status
    if status == 404:
        assert isinstance(e.value, NotFoundError)
    else:
        assert isinstance(e.value, InternalServerError)


@pytest.mark.parametrize("node_class", ["urllib3", "requests"])
def test_get_404_request(node_class):
    t = Transport("https://httpbin.org", node_class=node_class)
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
