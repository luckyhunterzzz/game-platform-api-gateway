package com.gameplatform.apigateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Converter implementation that extracts user roles from a KeyCloak issued JWT.
 * It specifically looks for the realm_access.roles claim and maps them to Spring Security GrandAuthority
 * with the ROLE_ prefix.
 */
@Component
@Slf4j
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String ROLES ="roles";
    private static final String REALM_ACCESS = "realm_access";

    /**
     * Converts a JWT a collection of authorities based on Keycloak realm roles
     *
     * @param jwt the JSON web token to extract roles from.
     * @return  a collection of GrandAuthority, or an empty list if no roles are found.
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {

        return Optional.ofNullable(jwt.getClaimAsMap(REALM_ACCESS))
                .map(realmAccess -> realmAccess.get(ROLES))
                .filter(List. class::isInstance)
                .map(rolesObj -> {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) rolesObj;
                    return roles.stream()
                            .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                            .map(GrantedAuthority. class::cast)
                            .collect(Collectors.toList());
                })
                .orElseGet(() -> {
                    log.warn("No roles found in JWT claim 'realm_access' for user: {}", jwt.getSubject());
                    return Collections.emptyList();
                });
    }
}
