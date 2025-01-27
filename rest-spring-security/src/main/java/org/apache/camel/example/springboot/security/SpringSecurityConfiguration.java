package org.apache.camel.example.springboot.security;

import org.apache.camel.Exchange;
import org.apache.camel.component.spring.security.SpringSecurityAuthorizationPolicy;
import org.apache.camel.spi.Policy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration {

    private static final String CONSULTANT_ROLE = "consultant";
    private static final String SUPERVISOR_ROLE = "supervisor";

    private final KeycloakJwtConverter keycloakJwtTokenConverter;

    private JwtAuthenticationProvider jwtAuthenticationProvider;

    @Autowired
    public SpringSecurityConfiguration(KeycloakConfiguration properties, JwtDecoder jwtDecoder) {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        this.keycloakJwtTokenConverter = new KeycloakJwtConverter(jwtGrantedAuthoritiesConverter, properties);
        this.jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("supervisor").implies("consultant")
                .build();
    }


    @Bean
    public SecurityFilterChain configure(HttpSecurity http, JwtAuthenticationConverter converter) throws Exception {

        http.cors(cors-> cors.disable());

        http
                .csrf((csrf) -> csrf
                        .ignoringRequestMatchers("/*"))

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/api/v1/company**",
                                "/api/api-doc**",
                                "/openapi/**",
                                "/openapi").permitAll()
                        .anyRequest().authenticated());

        http
                .oauth2ResourceServer(
                        oauth2 ->oauth2.jwt(
                                jwtCustomizer ->{
                                    jwtCustomizer.jwtAuthenticationConverter(keycloakJwtTokenConverter);

                                }));

        http
                .sessionManagement(
                        session -> session.sessionCreationPolicy(STATELESS));
       // http.exceptionHandling(configurer -> configurer.authenticationEntryPoint(new Ht))
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(jwtAuthenticationProvider);
    }

    @Bean
    public Policy supervisorPolicy(AuthenticationManager authenticationManager, RoleHierarchy roleHierarchy) {
        AuthorityAuthorizationManager<Exchange> authorizationManager =  AuthorityAuthorizationManager.hasRole("supervisor");
        authorizationManager.setRoleHierarchy(roleHierarchy);
        SpringSecurityAuthorizationPolicy policy = new SpringSecurityAuthorizationPolicy();
        policy.setAuthenticationManager(authenticationManager);
        policy.setAuthorizationManager(authorizationManager);
        return policy;
    }

    @Bean
    public Policy consultantPolicy(AuthenticationManager authenticationManager, RoleHierarchy roleHierarchy) {
        AuthorityAuthorizationManager<Exchange> authorizationManager =  AuthorityAuthorizationManager.hasRole("consultant");
        authorizationManager.setRoleHierarchy(roleHierarchy);
        SpringSecurityAuthorizationPolicy policy = new SpringSecurityAuthorizationPolicy();
        policy.setAuthenticationManager(authenticationManager);
        policy.setAuthorizationManager(authorizationManager);
        return policy;
    }

    @Bean
    public MethodInvokingFactoryBean adminPolicy() {
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setTargetClass(SecurityContextHolder.class);
        methodInvokingFactoryBean.setTargetMethod("setStrategyName");
        methodInvokingFactoryBean.setArguments(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        return methodInvokingFactoryBean;
    }
}