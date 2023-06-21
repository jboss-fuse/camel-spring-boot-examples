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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration(proxyBeanMethods = false)
@ConfigurationProperties
public class OIDCLoginSecurityConfig {

    @Autowired
    Environment env;


    @Bean
    public JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter(){
        return new JwtGrantedAuthoritiesConverter();
    }

    @Bean
    public KeycloakJwtConverter keycloakJwtConverter(JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter) {
        return new KeycloakJwtConverter(jwtGrantedAuthoritiesConverter, env.getProperty("sso.service.client-id"));
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, KeycloakJwtConverter keycloakJwtConverter) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests(
                        authorizeRequests -> authorizeRequests
                                .antMatchers(GET, "/camel-rest-oidc/not-secured**").permitAll()
                                .antMatchers(GET, "/camel-rest-oidc/authenticated**").authenticated()
                                .antMatchers(GET, "/camel-rest-oidc/authorized**").hasRole("ADMIN")
                )
                .sessionManagement().sessionCreationPolicy(STATELESS)
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(keycloakJwtConverter);
        return http.build();
    }
}
