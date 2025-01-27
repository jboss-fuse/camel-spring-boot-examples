package org.apache.camel.example.springboot.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;


public class KeycloakJwtConverter implements Converter<Jwt, JwtAuthenticationToken> {


    private static final String RESOURCE_ACCESS = "resource_access";

    private static final String REALM_ACCESS = "realm_access";

    private static final String ROLES_KEY = "roles";

    private static final String ROLE_PREFIX = "ROLE_";

    private final KeycloakConfiguration keycloakConfiguration;

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter;


    public KeycloakJwtConverter(
            JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter,
            KeycloakConfiguration properties) {
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
        this.keycloakConfiguration = properties;
    }

    @Override
    public JwtAuthenticationToken convert(@NonNull Jwt jwt) {

        Collection<? extends GrantedAuthority> realm_roles = keycloakConfiguration.isIncludeRealmRoles() ? extractRealmRoles(jwt) : Set.of();

        Collection<? extends GrantedAuthority> resource_authorities = extractResourceRoles(jwt);

        Stream<? extends GrantedAuthority> roles = Stream.concat(realm_roles.stream(), resource_authorities.stream());

        Collection<? extends GrantedAuthority> authorities = Stream
                .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), roles)
                .collect(toSet());

        String principalClaimName = keycloakConfiguration.getPrincipalAttribute()
                .map(jwt::getClaimAsString)
                .orElse(jwt.getClaimAsString(JwtClaimNames.SUB));

        return new JwtAuthenticationToken(jwt, resource_authorities, principalClaimName);
    }

    private Collection<? extends GrantedAuthority> extractRealmRoles(Jwt jwt) {

        if (jwt.getClaim(REALM_ACCESS) == null) {
            return Set.of();
        }

        Map<String, Object> realmAccess = jwt.getClaim(REALM_ACCESS);

        if (realmAccess.get(ROLES_KEY) == null) {
            return Set.of();
        }

        Collection<String> realmRoles = (Collection<String>) realmAccess.get(ROLES_KEY);

        return realmRoles.stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .collect(toList());
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (jwt.getClaim(RESOURCE_ACCESS) == null) {
            return Set.of();
        }
        resourceAccess = jwt.getClaim(RESOURCE_ACCESS);

        if (resourceAccess.get(keycloakConfiguration.getResourceName()) == null) {
            return Set.of();
        }
        resource = (Map<String, Object>) resourceAccess.get(keycloakConfiguration.getResourceName());

        resourceRoles = (Collection<String>) resource.get(ROLES_KEY);
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .collect(toSet());
    }

}
