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
package org.apache.camel.example.spring.boot.monitoring;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.rest.RestBindingMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
public class MonitoredRouteBuilder extends RouteBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(MonitoredRouteBuilder.class);

    @Override
    public void configure() throws Exception {

        // First, we have to configure our jetty component, which will be the rest
        // in charge of querying the REST endpoints from actuator
        restConfiguration()
                .host("0.0.0.0")
                .port(8080)
                .bindingMode(RestBindingMode.json);

        // First, let's show the routes we have exposed. Let's create a timer
        // consumer that will only fire once and show us the exposed mappings
        from("timer:queryTimer?period={{metricsPeriod}}")
                .routeId("mappings-route")
                .to("rest:get:/actuator/mappings").id("to-actuator-mappings")
                .unmarshal()
                .json(true).id("unmarshal-mappings")
                .delay(simple("${random(500,5000)}"))
                .process(e->{
                    int random = new Random().nextInt(4320923);
                    if ( random % 7 == 0 ){
                        throw new Exception("Randomly generate a failure to increase the error statistics");
                    }
                }).id("random-failure-mappings")
                .to("micrometer:counter:simple.counter").id("to-counter-mappings")
                .to("log:camelroute?multiline=true&level=TRACE").id("to-log-mappings");



        // Then, we will be querying the cpu consumption periodically. For more options, you can check
        // https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-metrics-endpoint
        from("timer:metricsTimer?period={{metricsPeriod}}")
                .routeId("cpu-usage-route")
                .to("rest:get:/actuator/metrics/system.cpu.usage").id("to-actuator-cpu")
                .unmarshal()
                .json(true).id("unmarshal-cpu")
                .to("micrometer:counter:simple.counter").id("to-counter-cpu")

                .delay(simple("${random(500,5000)}"))
                .to("log:metricTimer?multiline=true&level=TRACE").id("to-log-cpu")
                .process(e->{
                    int random = new Random().nextInt(4320923);
                   if ( random % 7 == 0 ){
                       throw new Exception("Randomly generate a failure to increase the error statistics");
                   }
                }).id("random-failure-cpu");


        from("timer:googleTimer?period={{metricsPeriod}}")
                .routeId("dummy-api-call-route")
                .process(e->{
                    e.getMessage().setBody(new Random().nextInt(8), Integer.class);
                }).id("generate-random-delay")
                .toD("https://hub.dummyapis.com/delay?seconds=${body}").id("to-dummy-api")
                .to("micrometer:counter:dummy.call.counter").id("to-counter-dummy-api");
    }
}
