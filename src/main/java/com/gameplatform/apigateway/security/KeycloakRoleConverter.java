package com.gameplatform.apigateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * Converter implementation that extracts user roles from a KeyCloak issued JWT.
 * It specifically looks for the realm_access.roles claim and maps them to Spring Security GrandAuthority
 * with the ROLE_ prefix.
 */
@Component
@Slf4j
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final KeycloakAuthoritiesExtractor authoritiesExtractor;

    public KeycloakRoleConverter(KeycloakAuthoritiesExtractor authoritiesExtractor) {
        this.authoritiesExtractor = authoritiesExtractor;
    }

    /**
     * Converts a JWT a collection of authorities based on Keycloak realm roles
     *
     * @param jwt the JSON web token to extract roles from.
     * @return  a collection of GrandAuthority, or an empty list if no roles are found.
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = authoritiesExtractor.extract(jwt.getClaims());
        if (authorities.isEmpty()) {
            log.warn("No roles found in JWT claim 'realm_access' for user: {}", jwt.getSubject());
        }
        return authorities;
    }
}
