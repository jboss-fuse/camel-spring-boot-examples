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
package sample.camel;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class RestToAmqRouter extends RouteBuilder {

    @Override
    public void configure() {

        restConfiguration().inlineRoutes(false);

        rest("/jms")
            .consumes("text/plain")
            .produces("text/plain")
            .post().routeId("rest-send-message")
                .to("direct:jms-send-message");

        from("direct:jms-send-message")
                .routeId("jms-send-message")
            .to("jms:queue:{{jms.queue}}");

        from("jms:queue:{{jms.queue}}")
                .routeId("jms-receive-message")
                .to("log:jms-receive-message");
    }

}
