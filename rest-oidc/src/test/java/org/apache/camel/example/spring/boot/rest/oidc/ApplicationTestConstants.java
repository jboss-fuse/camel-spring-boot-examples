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

public interface ApplicationTestConstants {
    String ADMIN_ROLE = "admin";
    String AUTHENTICATED_USERNAME = "authenticated";
    String AUTHENTICATED_PASSWORD = "authenticated-pass";
    String AUTHORIZED_USERNAME = "authorized";
    String AUTHORIZED_PASSWORD = "autorized-pass";
    String CONTAINER_IMAGE = "registry.redhat.io/rh-sso-7/sso76-openshift-rhel8:7.6";
    int CONTAINER_PORT = 8080;
    int EXPOSED_PORT = 8080;
    String REST_SERVICE_CLIENT_ID = "service";
    String REST_SERVICE_CLIENT_SECRET = "service-pass";
    String REST_CONSUMER_CLIENT_ID = "consumer";
    String REST_CONSUMER_CLIENT_SECRET = "consumer-pass";
    int SERVER_PORT = 8082;
    String SSO_SERVER_URL = "http://localhost:" + EXPOSED_PORT +"/auth";
    String SSO_ADMIN_USERNAME = "admin";
    String SSO_ADMIN_PASSWORD = "admin-pass";
    String SSO_MASTER_REALM = "master";
    String SSO_REALM = "camel";
    String SSO_ADMIN_CLIENT_ID = "admin-cli";
}
