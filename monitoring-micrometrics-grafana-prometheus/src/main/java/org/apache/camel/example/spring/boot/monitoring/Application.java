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
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.jmx.BuildInfoMetrics;
import io.prometheus.jmx.JmxCollector;
import io.prometheus.metrics.model.registry.PrometheusRegistry;
import org.apache.camel.CamelContext;
import org.apache.camel.component.micrometer.MicrometerConstants;
import org.apache.camel.component.micrometer.eventnotifier.MicrometerExchangeEventNotifier;
import org.apache.camel.component.micrometer.eventnotifier.MicrometerRouteEventNotifier;
import org.apache.camel.component.micrometer.messagehistory.MicrometerMessageHistoryFactory;
import org.apache.camel.component.micrometer.routepolicy.MicrometerRoutePolicyFactory;
import org.apache.camel.spring.boot.CamelContextConfiguration;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;

import javax.management.MalformedObjectNameException;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

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
            PrometheusConfig prometheusConfig, PrometheusRegistry prometheusRegistry, Clock clock) throws MalformedObjectNameException, IOException {

        InputStream resource = new ClassPathResource("config/prometheus_exporter_config.yml").getInputStream();

        new JmxCollector(resource).register(prometheusRegistry);
        new BuildInfoMetrics().register(prometheusRegistry);
        return new PrometheusMeterRegistry(prometheusConfig, prometheusRegistry, clock);
    }

    @Bean
    public CamelContextConfiguration camelContextConfiguration(@Autowired PrometheusMeterRegistry registry, @Autowired CamelContext camelContext) {

        return new CamelContextConfiguration() {
            @Override
            public void beforeApplicationStart(CamelContext camelContext) {
                MicrometerRoutePolicyFactory micrometerRoutePolicyFactory = new MicrometerRoutePolicyFactory();
                micrometerRoutePolicyFactory.setMeterRegistry(registry);
                micrometerRoutePolicyFactory.setCamelContext(camelContext);
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

    @Bean("dummyapisSslContext")
    public SSLContextParameters dummyapisSslContext() {
        final SSLContextParameters sslContextParameters = new SSLContextParameters();

        /*
        since https://hub.dummyapis.com doesn't have a valid certifcate
        , and since this is an example, we can simply solve trusting all
        the certifcates. this is STRONGLY discouraged on production
        environment

        this SSL context is used only in the specific Camel route, not
        application wide
         */
        final TrustManagersParameters tmp = new TrustManagersParameters();
        tmp.setTrustManager(new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[] {};
            }
        });

        sslContextParameters.setTrustManagers(tmp);

        return sslContextParameters;
    }
}
