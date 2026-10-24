package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2SessionRefreshWebFilterTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private ReactiveOAuth2AuthorizedClientManager clientManager;
    private ServerOAuth2AuthorizedClientRepository clientRepository;
    private RedisRefreshLockService lockService;
    private ReactiveJwtDecoder jwtDecoder;
    private ServerSecurityContextRepository securityContextRepository;
    private OAuth2SessionRefreshWebFilter filter;

    @BeforeEach
    void setUp() {
        clientManager = mock(ReactiveOAuth2AuthorizedClientManager.class);
        clientRepository = mock(ServerOAuth2AuthorizedClientRepository.class);
        lockService = mock(RedisRefreshLockService.class);
        jwtDecoder = mock(ReactiveJwtDecoder.class);
        securityContextRepository = mock(ServerSecurityContextRepository.class);
        filter = new OAuth2SessionRefreshWebFilter(
                clientManager,
                clientRepository,
                jwtDecoder,
                new KeycloakAuthoritiesExtractor(),
                lockService,
                securityContextRepository,
                Duration.ofSeconds(60),
                Duration.ofSeconds(30),
                Duration.ofSeconds(10),
                "GAME_SESSION",
                false,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void passesRequestThroughOnceWhenTokenDoesNotNeedRefresh() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient client = authorizedClient(NOW.plusSeconds(300));
        MockServerWebExchange exchange = exchange(authentication);
        AtomicInteger chainCalls = new AtomicInteger();
        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(client));

        filter.filter(exchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        }).block();

        assertThat(chainCalls).hasValue(1);
        verify(clientManager, never()).authorize(any());
        verify(lockService, never()).tryAcquire(anyString(), any());
    }

    @Test
    void doesNotRefreshWhilePreparingOrPerformingLogout() {
        OAuth2AuthenticationToken authentication = authentication();
        AtomicInteger chainCalls = new AtomicInteger();
        MockServerWebExchange csrfExchange = MockServerWebExchange.builder(
                        MockServerHttpRequest.get("/api/session/csrf"))
                .principal(authentication)
                .build();
        MockServerWebExchange logoutExchange = MockServerWebExchange.builder(
                        MockServerHttpRequest.post("/api/logout"))
                .principal(authentication)
                .build();

        filter.filter(csrfExchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        }).block();
        filter.filter(logoutExchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        }).block();

        assertThat(chainCalls).hasValue(2);
        verify(clientRepository, never()).loadAuthorizedClient(anyString(), any(), any());
        verify(clientManager, never()).authorize(any());
    }

    @Test
    void returnsServiceUnavailableWhenExpiredTokenIsLockedByAnotherRequest() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient client = authorizedClient(NOW.minusSeconds(1));
        MockServerWebExchange exchange = exchange(authentication);
        AtomicInteger chainCalls = new AtomicInteger();
        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(client));
        when(lockService.tryAcquire(anyString(), any())).thenReturn(Mono.empty());

        filter.filter(exchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("1");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Auth-Refresh-Pending")).isEqualTo("true");
        assertThat(chainCalls).hasValue(0);
    }

    @Test
    void sharesOneRefreshAcrossConcurrentRequestsForTheSameSession() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient currentClient = authorizedClient(NOW.minusSeconds(1));
        OAuth2AuthorizedClient refreshedClient = authorizedClient(NOW.plusSeconds(900));
        MockWebSession session = new MockWebSession();
        MockServerWebExchange firstExchange = exchange(authentication, session);
        MockServerWebExchange secondExchange = exchange(authentication, session);
        RedisRefreshLockService.RefreshLock lock = new RedisRefreshLockService.RefreshLock("lock", "owner");
        Sinks.One<OAuth2AuthorizedClient> refreshResult = Sinks.one();
        AtomicInteger chainCalls = new AtomicInteger();
        Jwt refreshedJwt = Jwt.withTokenValue("refreshed-access-token")
                .header("alg", "RS256")
                .subject("user-1")
                .issuedAt(NOW)
                .expiresAt(NOW.plusSeconds(900))
                .claim("realm_access", Map.of("roles", List.of("admin")))
                .build();

        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(currentClient));
        when(lockService.tryAcquire(anyString(), any())).thenReturn(Mono.just(lock));
        when(lockService.release(lock)).thenReturn(Mono.empty());
        when(clientManager.authorize(any())).thenReturn(refreshResult.asMono());
        when(jwtDecoder.decode("access-token")).thenReturn(Mono.just(refreshedJwt));
        when(securityContextRepository.save(any(), any())).thenReturn(Mono.empty());

        Mono<Void> firstRequest = filter.filter(firstExchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        });
        Mono<Void> secondRequest = filter.filter(secondExchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        });

        CompletableFuture<Void> requests = Mono.when(firstRequest, secondRequest).toFuture();
        refreshResult.tryEmitValue(refreshedClient);
        requests.join();

        assertThat(chainCalls).hasValue(2);
        assertThat(firstExchange.getResponse().getStatusCode()).isNull();
        assertThat(secondExchange.getResponse().getStatusCode()).isNull();
        verify(clientManager, times(1)).authorize(any());
        verify(lockService, times(1)).tryAcquire(anyString(), any());
        verify(lockService, times(1)).release(lock);
    }

    @Test
    void keepsSessionWhenRefreshFailsButAccessTokenIsStillValid() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient client = authorizedClient(NOW.plusSeconds(30));
        MockServerWebExchange exchange = exchange(authentication);
        AtomicInteger chainCalls = new AtomicInteger();
        RedisRefreshLockService.RefreshLock lock = new RedisRefreshLockService.RefreshLock("lock", "owner");
        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(client));
        when(lockService.tryAcquire(anyString(), any())).thenReturn(Mono.just(lock));
        when(lockService.release(lock)).thenReturn(Mono.empty());
        when(clientManager.authorize(any())).thenReturn(Mono.error(new IllegalStateException("Keycloak unavailable")));

        filter.filter(exchange, ignored -> {
            chainCalls.incrementAndGet();
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
        assertThat(chainCalls).hasValue(1);
    }

    @Test
    void invalidatesSessionWhenRefreshTokenIsRevoked() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient client = authorizedClient(NOW.minusSeconds(1));
        MockServerWebExchange exchange = exchange(authentication);
        RedisRefreshLockService.RefreshLock lock = new RedisRefreshLockService.RefreshLock("lock", "owner");
        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(client));
        when(clientRepository.removeAuthorizedClient(anyString(), any(), any())).thenReturn(Mono.empty());
        when(lockService.tryAcquire(anyString(), any())).thenReturn(Mono.just(lock));
        when(lockService.release(lock)).thenReturn(Mono.empty());
        when(clientManager.authorize(any())).thenReturn(Mono.error(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"))
        ));

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getCookies()).containsKeys("GAME_SESSION", "XSRF-TOKEN");
        assertThat(exchange.getSession().block().isStarted()).isFalse();
        verify(clientRepository).removeAuthorizedClient(anyString(), any(), any());
    }

    @Test
    void savesRefreshedRolesBeforeContinuingTheRequest() {
        OAuth2AuthenticationToken authentication = authentication();
        OAuth2AuthorizedClient currentClient = authorizedClient(NOW.plusSeconds(30));
        OAuth2AuthorizedClient refreshedClient = authorizedClient(NOW.plusSeconds(900));
        MockServerWebExchange exchange = exchange(authentication);
        RedisRefreshLockService.RefreshLock lock = new RedisRefreshLockService.RefreshLock("lock", "owner");
        AtomicReference<Authentication> routedAuthentication = new AtomicReference<>();
        Jwt refreshedJwt = Jwt.withTokenValue("refreshed-access-token")
                .header("alg", "RS256")
                .subject("user-1")
                .issuedAt(NOW)
                .expiresAt(NOW.plusSeconds(900))
                .claim("realm_access", Map.of("roles", List.of("admin")))
                .build();

        when(clientRepository.<OAuth2AuthorizedClient>loadAuthorizedClient(anyString(), any(), any()))
                .thenReturn(Mono.just(currentClient));
        when(lockService.tryAcquire(anyString(), any())).thenReturn(Mono.just(lock));
        when(lockService.release(lock)).thenReturn(Mono.empty());
        when(clientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
        when(jwtDecoder.decode("access-token")).thenReturn(Mono.just(refreshedJwt));
        when(securityContextRepository.save(any(), any())).thenReturn(Mono.empty());

        filter.filter(exchange, routedExchange -> routedExchange.getPrincipal()
                .cast(Authentication.class)
                .doOnNext(routedAuthentication::set)
                .then()).block();

        assertThat(routedAuthentication.get().getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .contains("ROLE_admin")
                .doesNotContain("ROLE_user");
        verify(securityContextRepository).save(any(), any());
        verify(lockService).release(lock);
    }

    private MockServerWebExchange exchange(OAuth2AuthenticationToken authentication) {
        return MockServerWebExchange.builder(MockServerHttpRequest.get("/api/v1/profile/me"))
                .principal(authentication)
                .build();
    }

    private MockServerWebExchange exchange(
            OAuth2AuthenticationToken authentication,
            MockWebSession session
    ) {
        return MockServerWebExchange.builder(MockServerHttpRequest.get("/api/v1/profile/me"))
                .session(session)
                .principal(authentication)
                .build();
    }

    private OAuth2AuthenticationToken authentication() {
        DefaultOAuth2User principal = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_user")),
                Map.of("sub", "user-1"),
                "sub"
        );
        return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), "keycloak");
    }

    private OAuth2AuthorizedClient authorizedClient(Instant expiresAt) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                NOW.minusSeconds(60),
                expiresAt,
                Set.of("openid")
        );
        return new OAuth2AuthorizedClient(clientRegistration(), "user-1", accessToken);
    }

    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("game-gateway")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://localhost/authorize")
                .tokenUri("http://localhost/token")
                .jwkSetUri("http://localhost/certs")
                .userInfoUri("http://localhost/userinfo")
                .userNameAttributeName("sub")
                .clientName("Keycloak")
                .build();
    }
}
