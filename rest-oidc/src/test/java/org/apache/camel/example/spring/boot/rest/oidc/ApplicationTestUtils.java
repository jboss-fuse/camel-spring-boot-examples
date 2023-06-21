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

import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.core.Response;
import java.util.List;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static org.apache.camel.example.spring.boot.rest.oidc.ApplicationTestConstants.SSO_REALM;
import static org.keycloak.representations.idm.CredentialRepresentation.PASSWORD;


public class ApplicationTestUtils {

    public static String createClient(Keycloak keycloak, String clientId, String clientSecret) {
        ClientRepresentation client = new ClientRepresentation();
        client.setId(clientId);
        client.setSecret(clientSecret);
        client.setServiceAccountsEnabled(true);
        client.setPublicClient(false);
        client.setDirectAccessGrantsEnabled(true);
        Response response = keycloak.realm(SSO_REALM).clients().create(client);
        String clientIdentifier = CreatedResponseUtil.getCreatedId(response);
        response.close();
        return clientIdentifier;
    }

    public static String createUser(Keycloak keycloak, String username, String password, RoleRepresentation role) {
        UserRepresentation representation = new UserRepresentation();
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setTemporary(false);
        credentialRepresentation.setType(PASSWORD);
        credentialRepresentation.setValue(password);
        representation.setUsername(username);
        representation.setCredentials(List.of(credentialRepresentation));
        representation.setEmailVerified(true);
        representation.setEnabled(true);
        Response response = keycloak.realm(SSO_REALM).users().create(representation);
        String userId = CreatedResponseUtil.getCreatedId(response);
        if(isNull(role)){
            return userId;
        }
        UserResource userResource = keycloak.realm(SSO_REALM).users().get(userId);
        userResource.roles().realmLevel().add(List.of(role));
        return userId;
    }

    public static String createUser(Keycloak keycloak, String username, String password) {
        return createUser(keycloak, username, password, null);
    }

    public static RoleRepresentation createRole(Keycloak keycloak, String roleName, String clientId) {
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setComposite(false);
        roleRepresentation.setName(roleName);

        if(nonNull(clientId)){
            roleRepresentation.setContainerId(clientId);
            roleRepresentation.setClientRole(true);
        } else {
            roleRepresentation.setContainerId(SSO_REALM);
        }

        keycloak.realm(SSO_REALM).roles().create(roleRepresentation);
        RoleResource roleCreated = keycloak.realm(SSO_REALM).roles().get(roleName);
        if (isNull(roleCreated)){
            return null;
        }

        return roleCreated.toRepresentation();
    }

    public static RoleRepresentation createRole(Keycloak keycloak, String role){
        return createRole( keycloak,  role, null);
    }
}
