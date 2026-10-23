package com.gameplatform.apigateway.controller;

import org.springframework.http.CacheControl;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/api/session")
public class SessionController {

    @GetMapping
    public Mono<SessionResponse> session(ServerWebExchange exchange) {
        preventCaching(exchange);
        return exchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(Authentication.class)
                .filter(this::isAuthenticatedUser)
                .map(this::authenticatedResponse)
                .defaultIfEmpty(SessionResponse.anonymous());
    }

    @GetMapping("/csrf")
    public Mono<CsrfResponse> csrf(ServerWebExchange exchange) {
        preventCaching(exchange);
        Object csrfAttribute = exchange.getAttribute(CsrfToken.class.getName());
        if (csrfAttribute instanceof Mono<?> csrfToken) {
            return csrfToken.cast(CsrfToken.class).map(CsrfResponse::from);
        }
        if (csrfAttribute instanceof CsrfToken csrfToken) {
            return Mono.just(CsrfResponse.from(csrfToken));
        }
        return Mono.error(new IllegalStateException("CSRF token is not available"));
    }

    private boolean isAuthenticatedUser(Authentication authentication) {
        return authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private SessionResponse authenticatedResponse(Authentication authentication) {
        Identity identity = extractIdentity(authentication);
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .sorted()
                .toList();

        return new SessionResponse(
                true,
                new SessionUser(identity.id(), identity.username(), identity.email(), roles)
        );
    }

    private Identity extractIdentity(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            Jwt jwt = jwtAuthentication.getToken();
            return new Identity(
                    jwt.getSubject(),
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getClaimAsString("email")
            );
        }

        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            return new Identity(
                    oidcUser.getSubject(),
                    oidcUser.getPreferredUsername(),
                    oidcUser.getEmail()
            );
        }

        return new Identity(
                authentication.getName(),
                authentication.getName(),
                null
        );
    }

    private void preventCaching(ServerWebExchange exchange) {
        exchange.getResponse().getHeaders().setCacheControl(CacheControl.noStore());
    }

    public record SessionResponse(boolean authenticated, SessionUser user) {

        public static SessionResponse anonymous() {
            return new SessionResponse(false, null);
        }
    }

    public record SessionUser(String id, String username, String email, List<String> roles) {
    }

    public record CsrfResponse(String headerName, String parameterName, String token) {

        public static CsrfResponse from(CsrfToken token) {
            return new CsrfResponse(token.getHeaderName(), token.getParameterName(), token.getToken());
        }
    }

    private record Identity(String id, String username, String email) {
    }
}
