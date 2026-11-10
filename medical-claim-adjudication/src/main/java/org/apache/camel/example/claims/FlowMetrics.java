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

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.apache.camel.CamelContext;
import org.apache.camel.Route;
import org.apache.camel.ServiceStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Reads existing meters without registering meters, performing lookups, or invoking inference. */
@Component
public class FlowMetrics {
    public static final String TOOL_ROUTE_ID = "flow-metrics-tool";
    private final MeterRegistry registry;
    private final CamelContext context;
    private final String instanceId;

    public FlowMetrics(MeterRegistry registry, CamelContext context,
                       @Value("${claims.instance-id}") String instanceId) {
        this.registry = registry;
        this.context = context;
        this.instanceId = instanceId;
    }

    public Snapshot snapshot(String routeId) {
        if (routeId != null && !Identifiers.valid(routeId)) {
            throw new IllegalArgumentException("routeId must be an existing route identifier");
        }
        List<Route> selected = context.getRoutes().stream()
                // The metrics request itself is in flight while this snapshot is being read.
                .filter(route -> !TOOL_ROUTE_ID.equals(route.getRouteId()))
                .filter(route -> routeId == null || routeId.equals(route.getRouteId()))
                .sorted(Comparator.comparing(Route::getRouteId)).toList();
        if (routeId != null && selected.isEmpty()) {
            throw new IllegalArgumentException("Unknown routeId; omit it to list the available application routes");
        }
        String capturedAt = Instant.now().toString();
        return new Snapshot(instanceId, context.getName(), capturedAt,
                Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime()).toString(),
                "Current instance only; counters are cumulative since meter registration; reads are not atomic. "
                        + "Missing measurements are null. Timer maxima cover the registry's rolling window. "
                        + "Route timings include nested work. Business outcomes and AI token usage are not measured.",
                selected.stream().map(this::routeMetrics).toList(), runtimeMetrics());
    }

    private RouteMetrics routeMetrics(Route route) {
        String id = route.getRouteId();
        ServiceStatus status = context.getRouteController().getRouteStatus(id);
        String[] tags = {"camelContext", context.getName(), "routeId", id};
        return new RouteMetrics(id, status == null ? null : status.name(),
                counter("camel.exchanges.total", tags), counter("camel.exchanges.succeeded", tags),
                counter("camel.exchanges.failed", tags), counter("camel.exchanges.failures.handled", tags),
                counter("camel.exchanges.external.redeliveries", tags), gauge("camel.exchanges.inflight", tags),
                timing("camel.route.policy", tags));
    }

    private RuntimeMetrics runtimeMetrics() {
        List<PoolMetrics> pools = registry.find("hikaricp.connections.max").gauges().stream()
                .map(gauge -> gauge.getId().getTag("pool")).filter(name -> name != null)
                .distinct().sorted().map(name -> new PoolMetrics(name,
                        gauge("hikaricp.connections.active", "pool", name),
                        gauge("hikaricp.connections.idle", "pool", name),
                        gauge("hikaricp.connections.max", "pool", name),
                        gauge("hikaricp.connections.pending", "pool", name),
                        timing("hikaricp.connections.acquire", "pool", name))).toList();
        return new RuntimeMetrics(gauge("process.uptime"), gauge("process.cpu.usage"),
                sumGauges("jvm.memory.used", "area", "heap"),
                sumGauges("jvm.memory.committed", "area", "heap"),
                gauge("jvm.threads.live"), pools);
    }

    private Double counter(String name, String... tags) {
        Counter counter = registry.find(name).tags(tags).counter();
        return counter == null ? null : finite(counter.count());
    }

    private Double gauge(String name, String... tags) {
        Gauge gauge = registry.find(name).tags(tags).gauge();
        return gauge == null ? null : finite(gauge.value());
    }

    private Double sumGauges(String name, String... tags) {
        var gauges = registry.find(name).tags(tags).gauges();
        if (gauges.isEmpty()) return null;
        return finite(gauges.stream().mapToDouble(Gauge::value).sum());
    }

    private Timing timing(String name, String... tags) {
        Timer timer = registry.find(name).tags(tags).timer();
        if (timer == null) return null;
        long count = timer.count();
        double totalMillis = timer.totalTime(TimeUnit.MILLISECONDS);
        return new Timing(count, finite(totalMillis), count == 0 ? null : finite(totalMillis / count),
                finite(timer.max(TimeUnit.MILLISECONDS)));
    }

    private Double finite(double value) {
        return Double.isFinite(value) ? value : null;
    }

    public record Snapshot(String instanceId, String camelContext, String snapshotAt, String processStartedAt,
                           String measurementScope, List<RouteMetrics> routes, RuntimeMetrics runtime) {
    }

    public record RouteMetrics(String routeId, String state, Double processed, Double succeeded, Double failed,
                               Double handledFailures, Double externalRedeliveries, Double inFlight, Timing timing) {
    }

    public record Timing(long count, Double totalMillis, Double meanMillis, Double windowMaxMillis) {
    }

    public record RuntimeMetrics(Double uptimeSeconds, Double processCpuRatio, Double heapUsedBytes,
                                 Double heapCommittedBytes, Double liveThreads, List<PoolMetrics> connectionPools) {
    }

    public record PoolMetrics(String pool, Double active, Double idle, Double max, Double pending, Timing acquisition) {
    }
}
