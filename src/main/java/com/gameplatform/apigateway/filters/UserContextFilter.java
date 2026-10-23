package com.gameplatform.apigateway.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
public class UserContextFilter implements GlobalFilter, Ordered {

    private static final List<String> SENSITIVE_HEADERS = List.of(
            "X-User-Id",
            "X-User-Roles",
            "X-User-Username",
            "X-User-Email"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest cleanedRequest = exchange.getRequest().mutate()
                .headers(headers -> SENSITIVE_HEADERS.forEach(headers::remove))
                .build();
        ServerWebExchange scrubbedExchange = exchange.mutate().request(cleanedRequest).build();

        return scrubbedExchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(Authentication.class)
                .map(authentication -> enrich(scrubbedExchange, authentication))
                .defaultIfEmpty(scrubbedExchange)
                .flatMap(chain::filter);
    }

    private ServerWebExchange enrich(ServerWebExchange exchange, Authentication authentication) {
        UserIdentity identity = extractIdentity(authentication);
        if (identity == null) {
            return exchange;
        }

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
        Optional.ofNullable(identity.id()).ifPresent(value -> requestBuilder.header("X-User-Id", value));
        Optional.ofNullable(identity.username()).ifPresent(value -> requestBuilder.header("X-User-Username", value));
        Optional.ofNullable(identity.email()).ifPresent(value -> requestBuilder.header("X-User-Email", value));

        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .distinct()
                .sorted()
                .collect(Collectors.joining(","));
        if (!roles.isEmpty()) {
            requestBuilder.header("X-User-Roles", roles);
        }

        log.debug("Enriched request for user ID {} with roles {}", identity.id(), roles);
        return exchange.mutate().request(requestBuilder.build()).build();
    }

    private UserIdentity extractIdentity(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            Jwt jwt = jwtAuthentication.getToken();
            return new UserIdentity(
                    jwt.getSubject(),
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getClaimAsString("email")
            );
        }

        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            return new UserIdentity(
                    oidcUser.getSubject(),
                    oidcUser.getPreferredUsername(),
                    oidcUser.getEmail()
            );
        }

        return null;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    private record UserIdentity(String id, String username, String email) {
    }
}
