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
package org.apache.camel.example.springboot.milvus;

import java.util.List;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ServiceStatus;
import org.apache.camel.example.springboot.milvus.bean.VectorUtils;
import org.apache.camel.support.DefaultExchange;

import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@CamelSpringBootTest
@SpringBootTest(classes = Application.class)
class MyCamelApplicationJUnit5Test {

    @Autowired
    private CamelContext camelContext;

    @Test
    void shouldLoadCamelContext() {
        assertEquals(ServiceStatus.Started, camelContext.getStatus());
    }

    @Test
    void shouldConvertSemicolonStringToFloatVector() throws Exception {
        VectorUtils vectorUtils = new VectorUtils();

        Exchange exchange = new DefaultExchange(camelContext);
        exchange.getIn().setBody("1.0;2.0;3.0");
        vectorUtils.process(exchange);

        @SuppressWarnings("unchecked")
        List<Float> vector = exchange.getIn().getBody(List.class);
        assertEquals(3, vector.size());
        assertEquals(1.0f, vector.get(0), 0.01f);
        assertEquals(2.0f, vector.get(1), 0.01f);
        assertEquals(3.0f, vector.get(2), 0.01f);
    }

    @Test
    void shouldNormalizeValuesToZeroOneRange() throws Exception {
        // Given a temperature range of 0-100 degrees
        VectorUtils vectorUtils = new VectorUtils();
        vectorUtils.setNormalizationRanges("0.0:100.0");

        // When we normalize 50 degrees (the midpoint)
        Exchange exchange = new DefaultExchange(camelContext);
        exchange.getIn().setBody("50.0");
        vectorUtils.process(exchange);

        @SuppressWarnings("unchecked")
        List<Float> vector = exchange.getIn().getBody(List.class);

        // Then the normalized value should be 0.5
        assertEquals(0.5f, vector.get(0), 0.01f);
    }

    @Test
    void shouldClampOutOfRangeValuesToZeroOne() throws Exception {
        // Given a range of 0-100
        VectorUtils vectorUtils = new VectorUtils();
        vectorUtils.setNormalizationRanges("0.0:100.0");

        // When we normalize a value above the max (150)
        Exchange exchange = new DefaultExchange(camelContext);
        exchange.getIn().setBody("150.0");
        vectorUtils.process(exchange);

        @SuppressWarnings("unchecked")
        List<Float> vector = exchange.getIn().getBody(List.class);

        // Then it should be clamped to 1.0 (the maximum)
        assertEquals(1.0f, vector.get(0), 0.01f);
    }

    @Test
    void shouldHandleMultipleDimensions() throws Exception {
        // Given ranges for height (cm) and weight (kg)
        VectorUtils vectorUtils = new VectorUtils();
        vectorUtils.setNormalizationRanges("100.0:200.0,30.0:130.0");

        // When we normalize 150cm height and 80kg weight
        Exchange exchange = new DefaultExchange(camelContext);
        exchange.getIn().setBody("150.0;80.0");
        vectorUtils.process(exchange);

        @SuppressWarnings("unchecked")
        List<Float> vector = exchange.getIn().getBody(List.class);

        // Then height 150 in range [100,200] => 0.5, weight 80 in range [30,130] => 0.5
        assertEquals(2, vector.size());
        assertEquals(0.5f, vector.get(0), 0.01f);
        assertEquals(0.5f, vector.get(1), 0.01f);
    }
}
