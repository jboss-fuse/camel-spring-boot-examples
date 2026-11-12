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

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.camel.CamelContext;
import org.apache.camel.Route;
import org.apache.camel.ServiceStatus;
import org.apache.camel.spi.RouteController;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class FlowMetricsTest {
    @Test
    void shouldSeparateCamelContextsAndConvertTimerUnitsWithoutCreatingMeters() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            String[] tags = {"camelContext", "this-context", "routeId", "sample-route"};
            Counter.builder("camel.exchanges.total").tags(tags).register(registry).increment(3);
            Counter.builder("camel.exchanges.succeeded").tags(tags).register(registry).increment(2);
            Counter.builder("camel.exchanges.failed").tags(tags).register(registry).increment();
            Counter.builder("camel.exchanges.total").tags("camelContext", "other-context", "routeId", "sample-route")
                    .register(registry).increment(100);
            AtomicInteger inFlight = new AtomicInteger(1);
            Gauge.builder("camel.exchanges.inflight", inFlight, AtomicInteger::get).tags(tags).register(registry);
            Timer timer = Timer.builder("camel.route.policy").tags(tags).register(registry);
            timer.record(Duration.ofMillis(250));
            timer.record(Duration.ofMillis(750));
            int meterCount = registry.getMeters().size();

            FlowMetrics metrics = new FlowMetrics(registry, context(), "instance-1");
            var result = metrics.snapshot("sample-route").routes().get(0);
            assertEquals(3.0, result.processed());
            assertEquals(2.0, result.succeeded());
            assertEquals(1.0, result.failed());
            assertEquals(1.0, result.inFlight());
            assertEquals(2, result.timing().count());
            assertEquals(1000.0, result.timing().totalMillis());
            assertEquals(500.0, result.timing().meanMillis());
            assertEquals(750.0, result.timing().windowMaxMillis());
            assertEquals(meterCount, registry.getMeters().size(), "Reads must not manufacture missing meters");
        } finally {
            registry.close();
        }
    }

    @Test
    void shouldRepresentUnavailableMeasurementsAsNullAndKeepKnownZeroValues() throws Exception {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            Counter.builder("camel.exchanges.total").tags("camelContext", "this-context", "routeId", "sample-route")
                    .register(registry);
            Gauge.builder("process.cpu.usage", () -> Double.NaN).register(registry);
            FlowMetrics metrics = new FlowMetrics(registry, context(), "instance-1");
            var snapshot = metrics.snapshot(null);
            var route = snapshot.routes().get(0);
            assertEquals(0.0, route.processed());
            assertNull(route.succeeded());
            assertNull(route.timing());
            assertNull(snapshot.runtime().processCpuRatio());
            assertNull(snapshot.runtime().heapUsedBytes());
            assertTrue(snapshot.runtime().connectionPools().isEmpty());
            String json = new ObjectMapper().writeValueAsString(snapshot);
            assertFalse(json.contains("NaN"));
            assertTrue(json.contains("\"succeeded\":null"));
            assertThrows(IllegalArgumentException.class, () -> metrics.snapshot("unknown"));
        } finally {
            registry.close();
        }
    }

    private CamelContext context() {
        CamelContext context = mock(CamelContext.class);
        Route route = mock(Route.class);
        RouteController controller = mock(RouteController.class);
        when(context.getName()).thenReturn("this-context");
        when(context.getRoutes()).thenReturn(List.of(route));
        when(route.getRouteId()).thenReturn("sample-route");
        when(context.getRouteController()).thenReturn(controller);
        when(controller.getRouteStatus("sample-route")).thenReturn(ServiceStatus.Started);
        return context;
    }
}
