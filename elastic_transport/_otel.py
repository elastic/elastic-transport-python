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

from __future__ import annotations

import contextlib
import os
from typing import Any, Generator, Mapping, Optional

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span

    _tracer: trace.Tracer | None = trace.get_tracer("elastic-transport")
except ModuleNotFoundError:
    _tracer = None


# Valid values for the enabled config are 'true' and 'false'. Default is 'true'.
ENABLED_ENV_VAR = "OTEL_PYTHON_INSTRUMENTATION_ELASTICSEARCH_ENABLED"
# Describes how to handle search queries in the request body when assigned to
# a span attribute.
# Valid values are 'omit' and 'raw'.
# Default is 'omit' as 'raw' has security implications.
BODY_STRATEGY_ENV_VAR = "OTEL_PYTHON_INSTRUMENTATION_ELASTICSEARCH_CAPTURE_SEARCH_QUERY"
DEFAULT_BODY_STRATEGY = "omit"

# A list of the Elasticsearch endpoints that qualify as "search" endpoints. The search query in
# the request body may be captured for these endpoints, depending on the body capture strategy.
SEARCH_ENDPOINTS = (
    "search",
    "async_search.submit",
    "msearch",
    "eql.search",
    "esql.query",
    "terms_enum",
    "search_template",
    "msearch_template",
    "render_search_template",
)


class OpenTelemetrySpan:
    def __init__(
        self,
        otel_span: Optional[Span],
        endpoint_id: Optional[str] = None,
        body_strategy: Optional[str] = None,
    ):
        self.otel_span = otel_span
        self.body_strategy = body_strategy
        self.endpoint_id = endpoint_id

    def set_node_metadata(
        self, host: str, port: int, base_url: str, target: str
    ) -> None:
        if self.otel_span is None:
            return

        # url.full does not contain auth info which is passed as headers
        self.otel_span.set_attribute("url.full", base_url + target)
        self.otel_span.set_attribute("server.address", host)
        self.otel_span.set_attribute("server.port", port)

    def set_elastic_cloud_metadata(self, headers: Mapping[str, str]) -> None:
        if self.otel_span is None:
            return

        cluster_name = headers.get("X-Found-Handling-Cluster")
        if cluster_name is not None:
            self.otel_span.set_attribute("db.elasticsearch.cluster.name", cluster_name)
        node_name = headers.get("X-Found-Handling-Instance")
        if node_name is not None:
            self.otel_span.set_attribute("db.elasticsearch.node.name", node_name)

    def set_db_statement(self, serialized_body: bytes) -> None:
        if self.otel_span is None:
            return

        print(f"{self.body_strategy=} {self.endpoint_id=}")

        if self.body_strategy == "omit":
            return
        elif self.body_strategy == "raw" and self.endpoint_id in SEARCH_ENDPOINTS:
            print("set", serialized_body)
            self.otel_span.set_attribute(
                "db.statement", serialized_body.decode("utf-8")
            )


class OpenTelemetry:
    def __init__(
        self,
        enabled: bool | None = None,
        tracer: trace.Tracer | None = None,
        body_strategy: str | None = None,
    ):
        if enabled is None:
            enabled = os.environ.get(ENABLED_ENV_VAR, "false") != "false"
        self.tracer = tracer or _tracer
        self.enabled = enabled and self.tracer is not None

        if body_strategy is not None:
            self.body_strategy = body_strategy
        else:
            self.body_strategy = os.environ.get(
                BODY_STRATEGY_ENV_VAR, DEFAULT_BODY_STRATEGY
            )

    @contextlib.contextmanager
    def span(
        self,
        method: str,
        *,
        endpoint_id: Optional[str],
        path_parts: Mapping[str, str],
    ) -> Generator[OpenTelemetrySpan, None, None]:
        if not self.enabled or self.tracer is None:
            yield OpenTelemetrySpan(None)
            return

        span_name = endpoint_id or method
        with self.tracer.start_as_current_span(span_name) as otel_span:
            otel_span.set_attribute("http.request.method", method)
            otel_span.set_attribute("db.system", "elasticsearch")
            if endpoint_id is not None:
                otel_span.set_attribute("db.operation", endpoint_id)
            for key, value in path_parts.items():
                otel_span.set_attribute(f"db.elasticsearch.path_parts.{key}", value)

            yield OpenTelemetrySpan(
                otel_span,
                endpoint_id=endpoint_id,
                body_strategy=self.body_strategy,
            )
