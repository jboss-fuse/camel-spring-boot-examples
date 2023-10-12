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

import io.micrometer.core.instrument.Clock;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.jmx.BuildInfoCollector;
import io.prometheus.jmx.JmxCollector;
import org.apache.camel.CamelContext;
import org.apache.camel.component.micrometer.MicrometerConstants;
import org.apache.camel.component.micrometer.eventnotifier.MicrometerExchangeEventNotifier;
import org.apache.camel.component.micrometer.eventnotifier.MicrometerRouteEventNotifier;
import org.apache.camel.component.micrometer.messagehistory.MicrometerMessageHistoryFactory;
import org.apache.camel.component.micrometer.routepolicy.MicrometerRoutePolicyFactory;
import org.apache.camel.spring.boot.CamelContextConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;

import javax.management.MalformedObjectNameException;
import java.io.IOException;
import java.io.InputStream;


/**
 * A sample Spring Boot application that starts the Camel routes.
 */
@SpringBootApplication
public class Application {
    /**
     * A main method to start this application.
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }


    @Bean(name = {MicrometerConstants.METRICS_REGISTRY_NAME, "prometheusMeterRegistry"})
    public PrometheusMeterRegistry prometheusMeterRegistry(
            PrometheusConfig prometheusConfig, CollectorRegistry collectorRegistry, Clock clock) throws MalformedObjectNameException, IOException {

        InputStream resource = new ClassPathResource("config/prometheus_exporter_config.yml").getInputStream();

        new JmxCollector(resource).register(collectorRegistry);
        new BuildInfoCollector().register(collectorRegistry);
        return new PrometheusMeterRegistry(prometheusConfig, collectorRegistry, clock);
    }

    @Bean
    public CamelContextConfiguration camelContextConfiguration(@Autowired PrometheusMeterRegistry registry) {

        return new CamelContextConfiguration() {
            @Override
            public void beforeApplicationStart(CamelContext camelContext) {
                MicrometerRoutePolicyFactory micrometerRoutePolicyFactory = new MicrometerRoutePolicyFactory();
                micrometerRoutePolicyFactory.setMeterRegistry(registry);
                camelContext.addRoutePolicyFactory(micrometerRoutePolicyFactory);

                MicrometerMessageHistoryFactory micrometerMessageHistoryFactory = new MicrometerMessageHistoryFactory();
                micrometerMessageHistoryFactory.setMeterRegistry(registry);
                camelContext.setMessageHistoryFactory(micrometerMessageHistoryFactory);

                MicrometerExchangeEventNotifier micrometerExchangeEventNotifier =  new MicrometerExchangeEventNotifier();
                micrometerExchangeEventNotifier.setMeterRegistry(registry);
                camelContext.getManagementStrategy().addEventNotifier(micrometerExchangeEventNotifier);

                MicrometerRouteEventNotifier micrometerRouteEventNotifier = new MicrometerRouteEventNotifier();
                micrometerRouteEventNotifier.setMeterRegistry(registry);
                camelContext.getManagementStrategy().addEventNotifier(micrometerRouteEventNotifier);

            }

            @Override
            public void afterApplicationStart(CamelContext camelContext) {
            }
        };
    }
}