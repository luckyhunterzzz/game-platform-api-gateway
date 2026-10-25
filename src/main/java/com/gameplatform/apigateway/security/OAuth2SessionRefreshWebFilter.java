package com.gameplatform.apigateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.context.SecurityContextServerWebExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
public class OAuth2SessionRefreshWebFilter implements WebFilter {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String REFRESH_PENDING_HEADER = "X-Auth-Refresh-Pending";
    private static final Set<String> REFRESH_BYPASS_PATHS = Set.of(
            "/api/session/csrf",
            "/api/logout"
    );

    private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
    private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ReactiveJwtDecoder jwtDecoder;
    private final KeycloakAuthoritiesExtractor authoritiesExtractor;
    private final RedisRefreshLockService refreshLockService;
    private final ServerSecurityContextRepository securityContextRepository;
    private final Duration refreshClockSkew;
    private final Duration lockTtl;
    private final Duration refreshRequestTimeout;
    private final String sessionCookieName;
    private final boolean secureCookie;
    private final Clock clock;

    public OAuth2SessionRefreshWebFilter(
            ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            ReactiveJwtDecoder jwtDecoder,
            KeycloakAuthoritiesExtractor authoritiesExtractor,
            RedisRefreshLockService refreshLockService,
            ServerSecurityContextRepository securityContextRepository,
            Duration refreshClockSkew,
            Duration lockTtl,
            Duration refreshRequestTimeout,
            String sessionCookieName,
            boolean secureCookie
    ) {
        this(
                authorizedClientManager,
                authorizedClientRepository,
                jwtDecoder,
                authoritiesExtractor,
                refreshLockService,
                securityContextRepository,
                refreshClockSkew,
                lockTtl,
                refreshRequestTimeout,
                sessionCookieName,
                secureCookie,
                Clock.systemUTC()
        );
    }

    OAuth2SessionRefreshWebFilter(
            ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            ReactiveJwtDecoder jwtDecoder,
            KeycloakAuthoritiesExtractor authoritiesExtractor,
            RedisRefreshLockService refreshLockService,
            ServerSecurityContextRepository securityContextRepository,
            Duration refreshClockSkew,
            Duration lockTtl,
            Duration refreshRequestTimeout,
            String sessionCookieName,
            boolean secureCookie,
            Clock clock
    ) {
        this.authorizedClientManager = authorizedClientManager;
        this.authorizedClientRepository = authorizedClientRepository;
        this.jwtDecoder = jwtDecoder;
        this.authoritiesExtractor = authoritiesExtractor;
        this.refreshLockService = refreshLockService;
        this.securityContextRepository = securityContextRepository;
        this.refreshClockSkew = refreshClockSkew;
        this.lockTtl = lockTtl;
        this.refreshRequestTimeout = refreshRequestTimeout;
        this.sessionCookieName = sessionCookieName;
        this.secureCookie = secureCookie;
        this.clock = clock;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (REFRESH_BYPASS_PATHS.contains(path)) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .filter(OAuth2AuthenticationToken.class::isInstance)
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(authentication -> refreshIfRequired(exchange, chain, authentication).thenReturn(true))
                .defaultIfEmpty(false)
                .flatMap(processed -> processed ? Mono.empty() : chain.filter(exchange));
    }

    private Mono<Void> refreshIfRequired(
            ServerWebExchange exchange,
            WebFilterChain chain,
            OAuth2AuthenticationToken authentication
    ) {
        String registrationId = authentication.getAuthorizedClientRegistrationId();
        return authorizedClientRepository
                .loadAuthorizedClient(registrationId, authentication, exchange)
                .flatMap(client -> {
                    if (!requiresRefresh(client)) {
                        return chain.filter(exchange).thenReturn(true);
                    }
                    return refreshWithLock(exchange, chain, authentication, client).thenReturn(true);
                })
                .switchIfEmpty(Mono.defer(() -> invalidateSession(exchange, authentication)
                        .then(writeStatus(exchange, HttpStatus.UNAUTHORIZED, true, false))
                        .thenReturn(true)))
                .flatMap(processed -> processed ? Mono.empty() : chain.filter(exchange));
    }

    private Mono<Void> refreshWithLock(
            ServerWebExchange exchange,
            WebFilterChain chain,
            OAuth2AuthenticationToken authentication,
            OAuth2AuthorizedClient currentClient
    ) {
        return exchange.getSession()
                .flatMap(session -> refreshWithDistributedLock(
                        session.getId(),
                        exchange,
                        authentication,
                        currentClient
                ))
                .onErrorResume(error -> {
                    log.warn("OAuth2 refresh infrastructure failed: {}", error.getClass().getSimpleName());
                    if (isAccessTokenValid(currentClient)) {
                        return Mono.just(RefreshOutcome.useCurrent());
                    }
                    return Mono.just(RefreshOutcome.unavailable());
                })
                .flatMap(outcome -> applyOutcome(exchange, chain, outcome));
    }

    private Mono<RefreshOutcome> refreshWithDistributedLock(
            String sessionId,
            ServerWebExchange exchange,
            OAuth2AuthenticationToken authentication,
            OAuth2AuthorizedClient currentClient
    ) {
        return refreshLockService.tryAcquire(sessionId, lockTtl)
                .flatMap(lock -> {
                    log.debug("OAuth2 refresh lock acquired: session={}", sessionFingerprint(sessionId));
                    return Mono.usingWhen(
                            Mono.just(lock),
                            ignored -> refreshAuthorizedClient(exchange, authentication, currentClient),
                            refreshLockService::release,
                            (ignored, error) -> refreshLockService.release(ignored),
                            refreshLockService::release
                    );
                })
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.debug("OAuth2 refresh lock is busy: session={}", sessionFingerprint(sessionId));
                    return lockBusyOutcome(currentClient);
                }));
    }

    private Mono<RefreshOutcome> refreshAuthorizedClient(
            ServerWebExchange exchange,
            OAuth2AuthenticationToken authentication,
            OAuth2AuthorizedClient currentClient
    ) {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withAuthorizedClient(currentClient)
                .principal(authentication)
                .attribute(ServerWebExchange.class.getName(), exchange)
                .build();

        return authorizedClientManager.authorize(authorizeRequest)
                .timeout(refreshRequestTimeout)
                .switchIfEmpty(Mono.error(new IllegalStateException("OAuth2 client refresh returned no client")))
                .flatMap(refreshedClient -> updateSecurityContext(exchange, authentication, refreshedClient))
                .onErrorResume(error -> handleRefreshFailure(exchange, authentication, currentClient, error));
    }

    private Mono<RefreshOutcome> updateSecurityContext(
            ServerWebExchange exchange,
            OAuth2AuthenticationToken authentication,
            OAuth2AuthorizedClient refreshedClient
    ) {
        if (!isAccessTokenValid(refreshedClient)) {
            return invalidateSession(exchange, authentication)
                    .thenReturn(RefreshOutcome.unauthorized());
        }

        return jwtDecoder.decode(refreshedClient.getAccessToken().getTokenValue())
                .flatMap(jwt -> {
                    Collection<GrantedAuthority> roles = authoritiesExtractor.extract(jwt.getClaims());
                    OAuth2AuthenticationToken refreshedAuthentication = withAuthorities(authentication, roles);
                    SecurityContext context = new SecurityContextImpl(refreshedAuthentication);
                    return saveRefreshedSecurityContext(exchange, context)
                            .thenReturn(RefreshOutcome.refreshed(context));
                });
    }

    private Mono<Void> saveRefreshedSecurityContext(
            ServerWebExchange exchange,
            SecurityContext context
    ) {
        // DefaultReactiveOAuth2AuthorizedClientManager has already placed the refreshed
        // authorized client into this WebSession. One explicit save persists both it and
        // the refreshed SecurityContext before the distributed lock is released.
        return securityContextRepository.save(exchange, context)
                .then(exchange.getSession().flatMap(session -> session.save()
                        .doOnSuccess(ignored -> log.debug(
                                "OAuth2 refresh persisted: session={}",
                                sessionFingerprint(session.getId())
                        ))));
    }

    private Mono<RefreshOutcome> handleRefreshFailure(
            ServerWebExchange exchange,
            OAuth2AuthenticationToken authentication,
            OAuth2AuthorizedClient currentClient,
            Throwable error
    ) {
        if (isInvalidGrant(error)) {
            log.info("OAuth2 refresh token is no longer valid; invalidating the user session");
            return invalidateSession(exchange, authentication)
                    .thenReturn(RefreshOutcome.unauthorized());
        }

        if (isAccessTokenValid(currentClient)) {
            log.warn("OAuth2 refresh failed while the current access token is still valid: {}",
                    error.getClass().getSimpleName());
            return Mono.just(RefreshOutcome.useCurrent());
        }

        log.warn("OAuth2 refresh failed after access token expiration: {}", error.getClass().getSimpleName());
        return Mono.just(RefreshOutcome.unavailable());
    }

    private Mono<Void> invalidateSession(ServerWebExchange exchange, OAuth2AuthenticationToken authentication) {
        return authorizedClientRepository
                .removeAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication, exchange)
                .onErrorResume(error -> {
                    log.warn("Failed to remove OAuth2 authorized client during session invalidation");
                    return Mono.empty();
                })
                .then(exchange.getSession().flatMap(session -> session.invalidate()
                        .onErrorResume(error -> {
                            log.warn("Failed to invalidate Redis WebSession");
                            return Mono.empty();
                        })))
                .then();
    }

    private Mono<Void> applyOutcome(
            ServerWebExchange exchange,
            WebFilterChain chain,
            RefreshOutcome outcome
    ) {
        if (outcome.status() != null) {
            return writeStatus(
                    exchange,
                    outcome.status(),
                    outcome.clearCookies(),
                    outcome.refreshPending()
            );
        }
        if (outcome.context() == null) {
            return chain.filter(exchange);
        }

        ServerWebExchange refreshedExchange = new SecurityContextServerWebExchange(
                exchange,
                Mono.just(outcome.context())
        );
        return chain.filter(refreshedExchange)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(outcome.context())));
    }

    private Mono<Void> writeStatus(
            ServerWebExchange exchange,
            HttpStatus status,
            boolean clearCookies,
            boolean refreshPending
    ) {
        if (clearCookies) {
            exchange.getResponse().addCookie(expiredCookie(sessionCookieName, true));
            exchange.getResponse().addCookie(expiredCookie("XSRF-TOKEN", false));
        }
        if (status == HttpStatus.SERVICE_UNAVAILABLE) {
            exchange.getResponse().getHeaders().set("Retry-After", "1");
        }
        if (refreshPending) {
            exchange.getResponse().getHeaders().set(REFRESH_PENDING_HEADER, "true");
        }
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    private ResponseCookie expiredCookie(String name, boolean httpOnly) {
        return ResponseCookie.from(name, "")
                .path("/")
                .httpOnly(httpOnly)
                .secure(secureCookie)
                .sameSite("Lax")
                .maxAge(Duration.ZERO)
                .build();
    }

    private OAuth2AuthenticationToken withAuthorities(
            OAuth2AuthenticationToken authentication,
            Collection<GrantedAuthority> refreshedRoles
    ) {
        LinkedHashSet<GrantedAuthority> authorities = new LinkedHashSet<>();
        authentication.getAuthorities().stream()
                .filter(authority -> !authority.getAuthority().startsWith(ROLE_PREFIX))
                .forEach(authorities::add);
        authorities.addAll(refreshedRoles);

        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            OidcUser refreshedUser = oidcUser.getUserInfo() == null
                    ? new DefaultOidcUser(authorities, oidcUser.getIdToken())
                    : new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
            return new OAuth2AuthenticationToken(
                    refreshedUser,
                    authorities,
                    authentication.getAuthorizedClientRegistrationId()
            );
        }

        return new OAuth2AuthenticationToken(
                authentication.getPrincipal(),
                authorities,
                authentication.getAuthorizedClientRegistrationId()
        );
    }

    private RefreshOutcome lockBusyOutcome(OAuth2AuthorizedClient currentClient) {
        if (isAccessTokenValid(currentClient)) {
            return RefreshOutcome.useCurrent();
        }
        log.warn("OAuth2 refresh is already running and the current access token has expired");
        return RefreshOutcome.refreshInProgress();
    }

    private String sessionFingerprint(String sessionId) {
        return Integer.toUnsignedString(sessionId.hashCode(), 16);
    }

    private boolean requiresRefresh(OAuth2AuthorizedClient client) {
        Instant expiresAt = client.getAccessToken().getExpiresAt();
        return expiresAt != null && !clock.instant().plus(refreshClockSkew).isBefore(expiresAt);
    }

    private boolean isAccessTokenValid(OAuth2AuthorizedClient client) {
        Instant expiresAt = client.getAccessToken().getExpiresAt();
        return expiresAt == null || clock.instant().isBefore(expiresAt);
    }

    private boolean isInvalidGrant(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof OAuth2AuthorizationException authorizationException
                    && "invalid_grant".equals(authorizationException.getError().getErrorCode())) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private record RefreshOutcome(
            SecurityContext context,
            HttpStatus status,
            boolean clearCookies,
            boolean refreshPending
    ) {

        private static RefreshOutcome refreshed(SecurityContext context) {
            return new RefreshOutcome(context, null, false, false);
        }

        private static RefreshOutcome useCurrent() {
            return new RefreshOutcome(null, null, false, false);
        }

        private static RefreshOutcome unauthorized() {
            return new RefreshOutcome(null, HttpStatus.UNAUTHORIZED, true, false);
        }

        private static RefreshOutcome unavailable() {
            return new RefreshOutcome(null, HttpStatus.SERVICE_UNAVAILABLE, false, false);
        }

        private static RefreshOutcome refreshInProgress() {
            return new RefreshOutcome(null, HttpStatus.SERVICE_UNAVAILABLE, false, true);
        }
    }
}
