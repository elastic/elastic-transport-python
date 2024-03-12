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
from typing import Generator, Mapping, Optional

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span

    _tracer: trace.Tracer | None = trace.get_tracer("elastic-transport")
except ModuleNotFoundError:
    _tracer = None


ENABLED_ENV_VAR = "OTEL_PYTHON_INSTRUMENTATION_ELASTICSEARCH_ENABLED"


class OpenTelemetrySpan:
    def __init__(self, otel_span: Optional[Span]):
        self.otel_span = otel_span

    def set_attribute(self, key: str, value: str) -> None:
        if self.otel_span is not None:
            self.otel_span.set_attribute(key, value)

    def set_elastic_cloud_metadata(self, headers: Mapping[str, str]) -> None:
        cluster_name = headers.get("X-Found-Handling-Cluster")
        if cluster_name is not None:
            self.set_attribute("db.elasticsearch.cluster.name", cluster_name)
        node_name = headers.get("X-Found-Handling-Instance")
        if node_name is not None:
            self.set_attribute("db.elasticsearch.node.name", node_name)


class OpenTelemetry:
    def __init__(self, enabled: bool | None = None, tracer: trace.Tracer | None = None):
        if enabled is None:
            enabled = os.environ.get(ENABLED_ENV_VAR, "false") != "false"
        self.tracer = tracer or _tracer
        self.enabled = enabled and self.tracer is not None

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
            yield OpenTelemetrySpan(otel_span)
