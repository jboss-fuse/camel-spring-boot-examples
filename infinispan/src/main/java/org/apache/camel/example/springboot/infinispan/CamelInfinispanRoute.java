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
package org.apache.camel.example.springboot.infinispan;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.infinispan.InfinispanConstants;
import org.apache.camel.component.infinispan.InfinispanOperation;

import org.apache.camel.component.infinispan.remote.InfinispanRemoteEventListener;
import org.apache.camel.impl.engine.DefaultShutdownStrategy;
import org.apache.camel.model.rest.ParamDefinition;
import org.apache.camel.model.rest.RestParamType;
import org.infinispan.client.hotrod.event.ClientEvent;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.camel.model.rest.RestParamType.path;

/**
 * A simple Camel Infinispan route example using Spring-boot
 */
@Component
public class CamelInfinispanRoute extends RouteBuilder {

    @Override
    public void configure() {

        restConfiguration().inlineRoutes(false);

        rest("/api/jdg")
                .produces(MediaType.TEXT_PLAIN_VALUE)
                .consumes(MediaType.TEXT_PLAIN_VALUE)
                .post()
                    .routeId("post-cache-item")
                    .param()
                        .name("id")
                        .type(RestParamType.query)
                        .dataType("string")
                    .endParam()
                .to("direct:put-cache");

        from("direct:put-cache")
            .routeId("put-cache")
            .setHeader(InfinispanConstants.OPERATION).constant(InfinispanOperation.PUT)
            .setHeader(InfinispanConstants.KEY).header("id")
            .setHeader(InfinispanConstants.VALUE).body(String.class)
            .log("PUT key : ${header.CamelInfinispanKey}, value : ${header.CamelInfinispanValue}")
            .to("infinispan://{{cache.name}}");

        from("infinispan://{{cache.name}}?eventTypes=CLIENT_CACHE_ENTRY_CREATED")
            .routeId("listen-new-cache-item")
            .log("Received headers: ${headers}")
            .process(exchange -> {
                Set<String> headers = new HashSet<>(exchange.getIn().getHeaders().keySet());
                headers.stream().filter(key -> !key.equals(InfinispanConstants.KEY))
                        .forEach(key -> exchange.getIn().removeHeader(key));
            })
            .to("direct:read-cache");

        from("direct:read-cache")
            .routeId("read-cache")
            .setHeader(InfinispanConstants.OPERATION).constant(InfinispanOperation.GET)
            .log("GET key : ${header." + InfinispanConstants.KEY + "}")
            .to("infinispan://{{cache.name}}")
            .log("Received body: ${body}");
    }

}
