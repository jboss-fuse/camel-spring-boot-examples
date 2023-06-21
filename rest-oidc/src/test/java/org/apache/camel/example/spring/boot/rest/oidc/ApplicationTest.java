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

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.function.Consumer;

import static org.apache.camel.Exchange.HTTP_RESPONSE_CODE;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.ADMIN_ROLE;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.AUTHENTICATED_PASSWORD;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.AUTHENTICATED_USERNAME;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.AUTHORIZED_PASSWORD;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.AUTHORIZED_USERNAME;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.CONTAINER_IMAGE;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.CONTAINER_PORT;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.EXPOSED_PORT;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.REST_CONSUMER_CLIENT_ID;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.REST_CONSUMER_CLIENT_SECRET;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.REST_SERVICE_CLIENT_ID;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.REST_SERVICE_CLIENT_SECRET;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SERVER_PORT;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_ADMIN_CLIENT_ID;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_ADMIN_PASSWORD;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_ADMIN_USERNAME;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_MASTER_REALM;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_REALM;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_SERVER_URL;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestUtils.createClient;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestUtils.createRole;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestUtils.createUser;
import static org.apache.camel.example.spring.boot.rest.oidc.RestCamelRouteBuilder.AUTHENTICATED_RESPONSE;
import static org.apache.camel.example.spring.boot.rest.oidc.RestCamelRouteBuilder.AUTHORIZED_RESPONSE;
import static org.apache.camel.example.spring.boot.rest.oidc.RestCamelRouteBuilder.NOT_SECURED_RESPONSE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;


@CamelSpringBootTest
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port = " + SERVER_PORT,
                "sso.realm = " + SSO_REALM,
                "sso.port = " + EXPOSED_PORT,
                "sso.service.client-id = " + REST_SERVICE_CLIENT_ID,
                "sso.service.client-secret = " + REST_SERVICE_CLIENT_SECRET
        })
public class ApplicationTest {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

    static GenericContainer container;


    @Autowired
    private ProducerTemplate producerTemplate;

    @BeforeAll
    public static void startServer() throws Exception {
        Consumer<CreateContainerCmd> cmd = e -> {
            e.withPortBindings(new PortBinding(Ports.Binding.bindPort(EXPOSED_PORT),
                    new ExposedPort(CONTAINER_PORT)));
        };

        container = new GenericContainer(CONTAINER_IMAGE)
                .withNetworkAliases("rhsso")
                .withExposedPorts(CONTAINER_PORT)
                .withCreateContainerCmdModifier(cmd)
                .withEnv("SSO_ADMIN_USERNAME", SSO_ADMIN_USERNAME)
                .withEnv("SSO_ADMIN_PASSWORD", SSO_ADMIN_PASSWORD)
                .withEnv("SSO_REALM", SSO_REALM)
                .waitingFor(Wait.forListeningPort())
                .waitingFor(Wait.forHttp("/auth/realms/camel/.well-known/openid-configuration"));

        container.start();

        //setup SSO clients and users

        try (Keycloak client = KeycloakBuilder.builder()
                .serverUrl(SSO_SERVER_URL)
                .username(SSO_ADMIN_USERNAME)
                .password(SSO_ADMIN_PASSWORD)
                .realm(SSO_MASTER_REALM)
                .clientId(SSO_ADMIN_CLIENT_ID)
                .build()) {

            ApplicationTestUtils.createClient(client, REST_SERVICE_CLIENT_ID, REST_SERVICE_CLIENT_SECRET);

            createClient(client, REST_CONSUMER_CLIENT_ID, REST_CONSUMER_CLIENT_SECRET);

            RoleRepresentation role = createRole(client, ADMIN_ROLE);

            createUser(client, AUTHORIZED_USERNAME, AUTHORIZED_PASSWORD, role);

            createUser(client, AUTHENTICATED_USERNAME, AUTHENTICATED_PASSWORD);
        }
    }

    @Test
    @DisplayName("anonymous user should access to not the secured endpoint")
    public void anonymousUserShouldAccessToNotSecuredEndpoint() throws InterruptedException {
        Exchange response = producerTemplate.send("http://localhost:" + SERVER_PORT + "/camel-rest-oidc/not-secured?httpMethod=GET", exchange -> {
            exchange.getIn().setBody("Hi!");
        });

        Integer responseStatus = response.getMessage().getHeader(HTTP_RESPONSE_CODE,  Integer.class);
        LOG.info("Received Response Code {}", responseStatus);
        assertFalse(response.isFailed());
        assertEquals(HttpStatus.OK.value(), responseStatus);
        assertEquals(NOT_SECURED_RESPONSE, response.getMessage().getBody(String.class));
    }

    @Test
    @DisplayName("authenticated user should access the secured endpoint")
    public void authenticatedUserShouldAccessToAuthenticatedEndpoint() throws InterruptedException {
        happyPath(AUTHENTICATED_USERNAME, AUTHENTICATED_PASSWORD, "authenticated", AUTHENTICATED_RESPONSE);
    }

    @Test
    @DisplayName("user with admin role should access the authorized endpoint")
    public void adminUserShouldAccessToAuthorizedEndpoint() throws InterruptedException {
        happyPath(AUTHORIZED_USERNAME, AUTHORIZED_PASSWORD, "authorized", AUTHORIZED_RESPONSE);
    }

    @Test
    @DisplayName("anonymous user should not access to the secured endpoint")
    public void anonymousUserShouldNotAccessToAuthenticatedEndpoint() throws InterruptedException {
        Exchange response = producerTemplate.send("http://localhost:" + SERVER_PORT + "/camel-rest-oidc/authenticated?httpMethod=GET&throwExceptionOnFailure=false", exchange -> {
            exchange.getIn().setBody("Hi!");
        });
        Integer responseStatus = response.getMessage().getHeader(HTTP_RESPONSE_CODE,  Integer.class);
        LOG.info("Received Response Code {}", responseStatus);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), responseStatus);
    }

    @Test
    @DisplayName("anonymous user should not access to the authorized endpoint")
    public void anonymousUserShouldNotAccessToAuthorizedEndpoint() throws InterruptedException {
        Exchange response = producerTemplate.send("http://localhost:" + SERVER_PORT + "/camel-rest-oidc/authorized?httpMethod=GET&throwExceptionOnFailure=false", exchange -> {
            exchange.getIn().setBody("Hi!");
        });

        Integer responseStatus = response.getMessage().getHeader(HTTP_RESPONSE_CODE,  Integer.class);
        LOG.info("Received Response Code {}", responseStatus);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), responseStatus);

    }


    @Test
    @DisplayName("authenticated user should not access to the authorized endpoint")
    public void authenticatedUserShouldNotAccessToAuthorizedEndpoint() throws InterruptedException {
        KeycloakClientFacade facade = new KeycloakClientFacade(SSO_SERVER_URL, SSO_REALM, REST_CONSUMER_CLIENT_ID, REST_CONSUMER_CLIENT_SECRET);
        String accessToken = facade.getAccessTokenString(AUTHENTICATED_USERNAME, AUTHENTICATED_PASSWORD);

        Exchange response = producerTemplate.send("http://localhost:" + SERVER_PORT + "/camel-rest-oidc/authorized?httpMethod=GET&throwExceptionOnFailure=false", exchange -> {
            exchange.getMessage().setHeader(AUTHORIZATION, "Bearer " + accessToken);
            exchange.getIn().setBody("Hi!");
        });

        Integer responseStatus = response.getMessage().getHeader(HTTP_RESPONSE_CODE,  Integer.class);
        LOG.info("Received Response Code {}", responseStatus);
        assertEquals(HttpStatus.FORBIDDEN.value(), responseStatus);
    }


    private void happyPath(String username, String password, String path, String expectedResponse) throws InterruptedException {
        KeycloakClientFacade facade = new KeycloakClientFacade(SSO_SERVER_URL, SSO_REALM, REST_CONSUMER_CLIENT_ID, REST_CONSUMER_CLIENT_SECRET);
        String accessToken = facade.getAccessTokenString(username, password);

        Exchange response = producerTemplate.send("http://localhost:" + SERVER_PORT + "/camel-rest-oidc/"+path+"?httpMethod=GET&throwExceptionOnFailure=false",
                exchange -> {
                    exchange.getMessage().setHeader(AUTHORIZATION, "Bearer " + accessToken);
                    exchange.getMessage().setBody("Hi!");
                });

        Integer responseStatus = response.getMessage().getHeader(HTTP_RESPONSE_CODE,  Integer.class);
        LOG.info("Received Response Code {}", responseStatus);

        assertEquals(HttpStatus.OK.value(), responseStatus);
        assertEquals(expectedResponse, response.getMessage().getBody(String.class));
    }
}
