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
package org.apache.camel.example.spring.boot.rest.oidc;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.rest.RestBindingMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;


@Component
public class RestCamelRouteBuilder extends RouteBuilder {

    public static final String NOT_SECURED_RESPONSE =  "Not secured endpoint!";
    public static final String AUTHENTICATED_RESPONSE = "You are authenticated user so you can perform this action.";
    public static final String AUTHORIZED_RESPONSE = "You are authorized to perform sensitive operation.";

    @Autowired
    private Environment env;

    @Override
    public void configure() {
        restConfiguration()
                .component("servlet")
                .contextPath("/camel-rest-oidc")

                .port(env.getProperty("server.port", "8082"))
                .bindingMode(RestBindingMode.auto);

        rest("/camel-rest-oidc").description("Books REST service")
                .get("/authenticated").description("Details of an order by id").to("direct:secured-authenticated")
                .get("/not-secured").description("The list of all the books").to("direct:not-secured")
                .get("/authorized").description("Details of an order by id").to("direct:secured-authorized");


        from("direct:not-secured")
                .setHeader(CONTENT_TYPE, constant(TEXT_PLAIN_VALUE))
                .setBody(constant(NOT_SECURED_RESPONSE));

        from("direct:secured-authenticated")
                .setHeader(CONTENT_TYPE, constant(TEXT_PLAIN_VALUE))
                .setBody(constant(AUTHENTICATED_RESPONSE));

        from("direct:secured-authorized")
                .setHeader(CONTENT_TYPE, constant(TEXT_PLAIN_VALUE))
                .setBody(constant(AUTHORIZED_RESPONSE));
    }
}
