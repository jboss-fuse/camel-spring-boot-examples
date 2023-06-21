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

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;

public class KeycloakClientFacade {

    private final String serverUrl;

    private final String realmId;

    private final String clientId;

    private final String clientSecret;

    public KeycloakClientFacade(String serverUrl, String realmId, String clientId, String clientSecret) {
        this.serverUrl = serverUrl;
        this.realmId = realmId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getAccessTokenString(String username, String password) {
        return getAccessTokenString(newKeycloakBuilderWithPasswordCredentials(username, password).build());
    }


    private String getAccessTokenString(Keycloak keycloak) {
        AccessTokenResponse tokenResponse = getAccessTokenResponse(keycloak);
        return tokenResponse == null ? null : tokenResponse.getToken();
    }

    private KeycloakBuilder newKeycloakBuilderWithPasswordCredentials(String username, String password) {
        return newKeycloakBuilderWithClientCredentials() //
                .username(username) //
                .password(password) //
                .grantType(OAuth2Constants.PASSWORD);
    }

    private KeycloakBuilder newKeycloakBuilderWithClientCredentials() {
        return KeycloakBuilder.builder() //
                .realm(realmId) //
                .serverUrl(serverUrl)//
                .clientId(clientId) //
                .clientSecret(clientSecret) //
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS);
    }

    private AccessTokenResponse getAccessTokenResponse(Keycloak keycloak) {
        try {
            return keycloak.tokenManager().getAccessToken();
        } catch (Exception ex) {
            return null;
        }
    }
}
