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

import org.apache.camel.component.jms.JmsComponent;
import org.apache.camel.spring.spi.SpringTransactionPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.transaction.PlatformTransactionManager;

import io.agroal.api.configuration.AgroalConnectionFactoryConfiguration;
import io.agroal.api.configuration.supplier.AgroalConnectionFactoryConfigurationSupplier;
import jakarta.jms.ConnectionFactory;

@SpringBootApplication
public class Application {
	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean(name = "PROPAGATION_REQUIRED")
	public SpringTransactionPolicy propagationRequired(PlatformTransactionManager jtaTransactionManager) {
		final SpringTransactionPolicy propagationRequired = new SpringTransactionPolicy();
		propagationRequired.setTransactionManager(jtaTransactionManager);
		propagationRequired.setPropagationBehaviorName("PROPAGATION_REQUIRED");
		return propagationRequired;
	}

	@Bean(name = "jms-component")
	public JmsComponent jmsComponent(ConnectionFactory xaJmsConnectionFactory, PlatformTransactionManager jtaTransactionManager) {
		final JmsComponent jms = new JmsComponent();
		jms.setConnectionFactory(xaJmsConnectionFactory);
		jms.setTransactionManager(jtaTransactionManager);
		jms.setTransacted(true);
		return jms;
	}

	/**
	 * Configure agroal to use XA datasources.
	 *
	 * @param datasourceClass datasource class
	 * @return agroal connectionfactory configuration
	 */
	@Bean
	AgroalConnectionFactoryConfiguration config(@Value("${xa.datasource.class}") String datasourceClass) {
		return new AgroalConnectionFactoryConfigurationSupplier().connectionProviderClassName(datasourceClass).get();
	}
}
