package com.gameplatform.apigateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

public class SessionCsrfProtectionMatcher implements ServerWebExchangeMatcher {

    private static final Set<HttpMethod> SAFE_METHODS = Set.of(
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
            HttpMethod.TRACE
    );

    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        HttpMethod method = exchange.getRequest().getMethod();
        if (SAFE_METHODS.contains(method)) {
            return MatchResult.notMatch();
        }

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return MatchResult.notMatch();
        }

        return MatchResult.match();
    }
}
