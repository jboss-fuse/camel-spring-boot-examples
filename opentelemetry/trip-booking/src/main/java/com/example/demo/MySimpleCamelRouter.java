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
package com.example.demo;

import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.apache.camel.model.rest.RestBindingMode;
import org.springframework.stereotype.Component;

@Component
public class MySimpleCamelRouter extends RouteBuilder {
    @Override
    public void configure() throws Exception {
        restConfiguration()
                .component("servlet")
                .bindingMode(RestBindingMode.json);

        rest()
                .get("/bookTrip").to("direct:bookTrip")
                .get("/asyncBookTrip").to("direct:asyncBookTrip");

        from("direct:bookTrip")
                .routeId("bookTrip-http")
                .routeDescription("This is demo service for demonstration telemetry aspects")
                .log(LoggingLevel.INFO, "New book trip request with trace=${header.traceparent}")
                .multicast(new MergeAggregationStrategy()).parallelProcessing()
                         .to("{{service.car}}/camel/bookCar?bridgeEndpoint=true")
                         .to("{{service.flight}}/camel/bookFlight?bridgeEndpoint=true")
                         .to("{{service.hotel}}/camel/bookHotel?bridgeEndpoint=true")
                .end()
                .log(LoggingLevel.INFO,"Response: ${body}")
                .unmarshal().json(JsonLibrary.Jackson);

        // kafka based 
        from("direct:asyncBookTrip")
                .routeId("bookTrip-kafka-request")
                .routeDescription("This is demo service for demonstration telemetry aspects via Kafka")
                .log(LoggingLevel.INFO, "New book trip request via Kafka")
                // .to("log:debug?showAll=true&multiline=true")
                .setBody(simple("New async request ${header.x-b3-traceid}"))
                .multicast().parallelProcessing()
                        .to("kafka:car_input")
                        .to("kafka:flight_input")
                        .to("kafka:hotel_input")
                .end();
        
        from("kafka:car_output").to("seda:tripAggregator");
        from("kafka:flight_output").to("seda:tripAggregator");
        from("kafka:hotel_output").to("seda:tripAggregator");
        
        from("seda:tripAggregator").routeId("bookTrip-kafka-response")
                .aggregate(constant(true), new MergeAggregationStrategy())
                .completionSize(3)
                .log(LoggingLevel.INFO, "New book trip response: ${body}");
    }
}
