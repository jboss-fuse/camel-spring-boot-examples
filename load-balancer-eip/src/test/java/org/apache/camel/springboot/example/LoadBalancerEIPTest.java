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
package org.apache.camel.springboot.example;

import org.apache.camel.CamelContext;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.apache.camel.test.spring.junit5.MockEndpoints;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@CamelSpringBootTest
@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@MockEndpoints("direct:*")
public class LoadBalancerEIPTest {

    @Autowired
    private CamelContext camelContext;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void roundRobinTest() throws Exception {
        final int messages = 10;
        final List<Integer> bodies = IntStream.range(0, messages).boxed().toList();

        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:roundrobin1", MockEndpoint.class);
        endpoint1.setExpectedCount(messages / 2);
        endpoint1.expectedBodiesReceived(bodies.stream().filter(i -> i % 2 == 0).map(String::valueOf).toArray());

        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:roundrobin2", MockEndpoint.class);
        endpoint2.setExpectedCount(messages / 2);
        endpoint2.expectedBodiesReceived(bodies.stream().filter(i -> i % 2 == 1).map(String::valueOf).toArray());

        for (int i = 0; i < messages; i++) {
            restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/round-robin/", i);
        }

        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

    @Test
    public void randomTest() {
        final int messages = 10;

        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:random1", MockEndpoint.class);
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:random2", MockEndpoint.class);

        for (int i = 0; i < messages; i++) {
            restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/random/", i);
        }

        assertEquals(messages, endpoint1.getReceivedCounter() + endpoint2.getReceivedCounter());
    }

    @Test
    public void stickyTest() throws Exception {
        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:sticky1", MockEndpoint.class);
        endpoint1.setExpectedCount(2);
        endpoint1.expectedBodiesReceived("A", "E");
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:sticky2", MockEndpoint.class);
        endpoint2.setExpectedCount(3);
        endpoint2.expectedBodiesReceived("B", "C", "D");

        HttpHeaders vowelHeader = new HttpHeaders();
        vowelHeader.set("correlation-key", "vowel");

        HttpHeaders consonantHeader = new HttpHeaders();
        consonantHeader.set("correlation-key", "consonant");

        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/sticky/", new HttpEntity<>("A", vowelHeader));
        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/sticky/", new HttpEntity<>("B", consonantHeader));
        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/sticky/", new HttpEntity<>("C", consonantHeader));
        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/sticky/", new HttpEntity<>("D", consonantHeader));
        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/sticky/", new HttpEntity<>("E", vowelHeader));

        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

    @Test
    public void topicTest() throws Exception {
        final int messages = 10;

        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:topic1", MockEndpoint.class);
        endpoint1.setExpectedCount(messages);
        endpoint1.expectedBodiesReceived(IntStream.range(0, messages).boxed().map(String::valueOf).toArray());
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:topic2", MockEndpoint.class);
        endpoint2.setExpectedCount(messages);
        endpoint2.expectedBodiesReceived(IntStream.range(0, messages).boxed().map(String::valueOf).toArray());

        for (int i = 0; i < messages; i++) {
            restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/topic/", i);
        }

        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

    @Test
    public void failoverTest() throws Exception {
        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:failover1", MockEndpoint.class);
        endpoint1.setExpectedCount(0);
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:failover2", MockEndpoint.class);
        endpoint1.setExpectedCount(1);

        restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/failover/", "A");

        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

    @Test
    public void weightTest() throws Exception {
        final int messages = 8;
        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:weighted1", MockEndpoint.class);
        endpoint1.setExpectedCount(6);
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:weighted2", MockEndpoint.class);
        endpoint2.setExpectedCount(2);

        for (int i = 0; i < messages; i++) {
            restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/weighted/", i);
        }
        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

    @Test
    public void customTest() throws Exception {
        final MockEndpoint endpoint1 = camelContext.getEndpoint("mock:direct:custom1", MockEndpoint.class);
        endpoint1.setExpectedCount(2);
        endpoint1.expectedBodiesReceived("A", "E");
        final MockEndpoint endpoint2 = camelContext.getEndpoint("mock:direct:custom2", MockEndpoint.class);
        endpoint2.setExpectedCount(3);
        endpoint2.expectedBodiesReceived("B", "C", "D");

        for (String s : List.of("A", "B", "C", "D", "E")) {
            restTemplate.postForLocation("http://localhost:" + port + "/loadbalancer/custom/", s);
        }

        endpoint1.assertIsSatisfied();
        endpoint2.assertIsSatisfied();
    }

}
