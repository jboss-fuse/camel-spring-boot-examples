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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.spring.junit6.CamelSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/** Opt-in: mvn -Dtest=ClaimModelIT test, with the real AI_BASE_URL/AI_MODEL configuration. */
@CamelSpringBootTest
@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "camel.main.run-controller=false",
        "claims.kafka.input-endpoint=direct:incoming",
        "claims.reviews.input-endpoint=direct:reviewResults",
        "claims.human-decisions.input-endpoint=direct:humanCommands",
        "claims.human-decisions.commands-endpoint=mock:humanCommands",
        "claims.kafka.results-endpoint=mock:results",
        "claims.kafka.failures-endpoint=mock:failures",
        "spring.datasource.url=jdbc:h2:mem:live-model-test;DB_CLOSE_DELAY=-1",
        "claims.instance-id=live-model-test"
})
class ClaimModelIT {
    @Autowired ProducerTemplate producer;
    @Autowired CamelContext context;
    @Value("${claims.model-test.samples:approved,excluded,over-limit,missing-coverage,human-approval}")
    String sampleSelection;

    private static String exceptionTypes(Throwable cause) {
        java.util.ArrayList<String> types = new java.util.ArrayList<>();
        for (Throwable current = cause; current != null; current = current.getCause()) {
            types.add(current.getClass().getSimpleName());
        }
        return types.toString();
    }

    @Test
    void shouldProcessEveryReadmeSampleWithTheConfiguredModel() throws Exception {
        ObjectMapper json = new ObjectMapper();
        MockEndpoint results = context.getEndpoint("mock:results", MockEndpoint.class);
        MockEndpoint failures = context.getEndpoint("mock:failures", MockEndpoint.class);
        List<String> samples = List.of(sampleSelection.split(","));
        var outcomes = java.util.Map.of("approved", "APPROVED", "excluded", "DENIED", "over-limit", "DENIED",
                "missing-coverage", "MANUAL_REVIEW", "human-approval", "MANUAL_REVIEW");
        for (int i = 0; i < samples.size(); i++) {
            String sample = samples.get(i);
            String input = Files.readString(Path.of("samples", sample + ".json"));
            Exchange completed = producer.request("direct:incoming", exchange -> exchange.getMessage().setBody(input));
            Throwable cause = completed.getProperty(Exchange.EXCEPTION_CAUGHT, Throwable.class);
            assertTrue(failures.getExchanges().isEmpty(), () -> "Model rejected " + sample + ": "
                    + failures.getExchanges().stream().map(exchange -> exchange.getMessage().getBody(String.class)).toList()
                    + "; recommendation: " + completed.getProperty("recommendation")
                    + "; exception types: " + exceptionTypes(cause));
            assertEquals(i + 1, results.getExchanges().size());
            var result = json.readTree(results.getExchanges().get(i).getMessage().getBody(String.class));
            assertEquals(outcomes.get(sample), result.path("outcome").asText(), sample);
        }
        producer.sendBody("direct:incoming", Files.readString(Path.of("samples", "invalid.json")));
        assertEquals(1, failures.getExchanges().size());
        assertEquals("INVALID_EVENT", json.readTree(failures.getExchanges().get(0).getMessage().getBody(String.class))
                .path("errorCode").asText());
    }
}
