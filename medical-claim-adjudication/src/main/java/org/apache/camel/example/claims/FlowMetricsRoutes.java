/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.example.claims;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.springframework.stereotype.Component;

/** Publishes instance metrics to external MCP clients using the existing review-tool tag. */
@Component
public class FlowMetricsRoutes extends RouteBuilder {
    private final FlowMetrics metrics;

    public FlowMetricsRoutes(FlowMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public void configure() {
        from("ai-tool:get_flow_metrics?tags={{claims.reviews.tool-tags}}"
                + "&description=Read cumulative route metrics and current JVM and connection-pool gauges for this instance; not claim history; missing meters are null"
                + "&parameter.routeId=string&parameter.routeId.description=Optional exact application route ID; omit to list all application routes"
                + "&readOnlyHint=true&idempotentHint=true")
            .routeId(FlowMetrics.TOOL_ROUTE_ID).startupOrder(25)
            .errorHandler(noErrorHandler())
            .process(exchange -> exchange.getMessage().setBody(
                    metrics.snapshot(exchange.getMessage().getHeader("routeId", String.class))))
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class);
    }
}
