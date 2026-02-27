package com.gameplatform.apigateway.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

/**
 * Global filter for security and user data.
 * It removes fake user headers and adds real user info from the JWT token.
 */
@Slf4j
@Component
public class UserContextFilter implements GlobalFilter, Ordered {

    private static final List<String> SENSITIVE_HEADERS = List.of("X-User-Id", "X-User-Roles", "X-User-Username");

    /**
     * Cleans the request and add verified user information
     * @param exchange the current server exchange
     * @param chain the filter chain
     * @return a Mono to continue the filter chain
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest cleanedRequest = exchange.getRequest().mutate()
                .headers(headers -> SENSITIVE_HEADERS.forEach(headers::remove))
                .build();
        ServerWebExchange scrubbedExchange = exchange.mutate().request(cleanedRequest).build();
        
        return scrubbedExchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(JwtAuthenticationToken::getToken)
                .map(jwt -> enrich(scrubbedExchange, jwt))
                .defaultIfEmpty(scrubbedExchange)
                .flatMap(chain::filter);
    }

    /**
     * Extract userId, username and roles from JWT and puts them into headers.
     */
    private ServerWebExchange enrich(ServerWebExchange scrubbedExchange, Jwt jwt) {
        ServerHttpRequest.Builder requestBuilder = scrubbedExchange.getRequest().mutate();

        String userId = jwt.getSubject();
        String username = jwt.getClaimAsString("preferred_username");

        String roles = extractRoles(jwt);

        Optional.ofNullable(userId).ifPresent(user -> requestBuilder.header("X-User-Id", user));
        Optional.ofNullable(username).ifPresent(user -> requestBuilder.header("X-User-Username", user));
        if(!roles.isEmpty()) {
            requestBuilder.header("X-User-Roles", roles);
        }

        log.debug("Enriched request for user: {} (ID: {}), roles: {}", username, userId, roles);

        return scrubbedExchange.mutate().request(requestBuilder.build()).build();
    }

    /**
     * Converts Keycloack roles from the JWT into a separated string
     */
    private String extractRoles(Jwt jwt) {
        return Optional.ofNullable(jwt.getClaimAsMap("realm_access"))
                .map(realmAccess -> realmAccess.get("roles"))
                .filter(List.class::isInstance)
                .map(rolesObj -> {
                    @SuppressWarnings("unchecked")
                    List<String> rolesList = (List<String>) rolesObj;
                    return String.join(",", rolesList);
                })
                .orElse("");
    }

    /**
     * Sets the order of this filter (it works after CorrelationFilter)
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}
