package org.apache.camel.example.springboot.security;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakConfiguration {

    private String resourceName;

    private String principalAttribute;

    private boolean includeRealmRoles = false;

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public Optional<String> getPrincipalAttribute() {
        return Optional.ofNullable(principalAttribute);
    }

    public void setPrincipalAttribute(String principalAttribute) {
        this.principalAttribute = principalAttribute;
    }

    public boolean isIncludeRealmRoles() {
        return includeRealmRoles;
    }

    public void setIncludeRealmRoles(boolean includeRealmRoles) {
        this.includeRealmRoles = includeRealmRoles;
    }
}
