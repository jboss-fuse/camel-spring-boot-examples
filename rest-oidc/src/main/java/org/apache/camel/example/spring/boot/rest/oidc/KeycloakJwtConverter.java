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

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import static java.util.Objects.isNull;
public class KeycloakJwtConverter implements Converter<Jwt, JwtAuthenticationToken> {

    private final Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter;
    private static final String principalClaimName = JwtClaimNames.SUB;

    private static final String REALM_ACCESS = "realm_access";

    private static final String RESOURCE_ACCESS = "resource_access";

    private static final String ROLES = "roles";

    private final SimpleAuthorityMapper mapper;

    private final String clientId;

    public KeycloakJwtConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter, String clientId) {
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
        this.clientId = clientId;
        this.mapper = new SimpleAuthorityMapper();
        this.mapper.setConvertToUpperCase(true);
    }

    @Override
    public JwtAuthenticationToken convert(Jwt source) {
        Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(source);
        if (isNull(authorities)){
            authorities = new ArrayList<>();
        }
        authorities.addAll(getResourcesRoles( source,  clientId));
        authorities.addAll(getRealmRoles(source));

        return new JwtAuthenticationToken(source, authorities, principalClaimName);
    }

    private  Collection<GrantedAuthority> getResourcesRoles(Jwt jwt, String clientId){

        Assert.notNull(jwt, "jwt token cannot be null");
        Assert.notNull(jwt.getClaims(), "jwt token have no claims");
        JSONObject resourceAccess = (JSONObject) jwt.getClaims().get(RESOURCE_ACCESS);

        if (isNull(resourceAccess)) {
            return new ArrayList<>();
        }

        JSONObject resources = (JSONObject) resourceAccess.get(clientId);

        if (isNull(resources)) {
            return new ArrayList<>();
        }

        JSONArray roles = (JSONArray)  resourceAccess.get(ROLES);

        return mapRoles(roles);
    }

    private  Collection<GrantedAuthority> getRealmRoles(Jwt jwt) {
        Assert.notNull(jwt, "jwt token cannot be null");
        Assert.notNull(jwt.getClaims(), "jwt token have no claims");
        Collection<GrantedAuthority> resourcesRoles = new ArrayList<>(5);
        JSONObject realmAccess = (JSONObject) jwt.getClaims().get(REALM_ACCESS);
        if (isNull(realmAccess)) {
            return new ArrayList<>();
        }

        JSONArray roles = (JSONArray) realmAccess.get(ROLES);
        return mapRoles(roles);
    }



        private Collection<GrantedAuthority> mapRoles(JSONArray roles) {
        if (isNull(roles) || roles.isEmpty()) {
            return new ArrayList<>();
        }
        String[] roleArray = roles.toArray(new String[0]);
        Collection<GrantedAuthority>  grantedAuthorities =  Arrays.stream(roleArray)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return  mapper.mapAuthorities(grantedAuthorities);
    }

}
