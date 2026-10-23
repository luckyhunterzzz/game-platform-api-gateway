package com.gameplatform.apigateway.config;

import com.gameplatform.apigateway.security.KeycloakAuthoritiesExtractor;
import com.gameplatform.apigateway.security.KeycloakLogoutSuccessHandler;
import com.gameplatform.apigateway.security.KeycloakOidcUserService;
import com.gameplatform.apigateway.security.KeycloakRoleConverter;
import com.gameplatform.apigateway.security.OAuth2SessionRefreshWebFilter;
import com.gameplatform.apigateway.security.RedisRefreshLockService;
import com.gameplatform.apigateway.security.SessionCsrfProtectionMatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final KeycloakRoleConverter keycloakRoleConverter;
    private final KeycloakAuthoritiesExtractor authoritiesExtractor;
    private final RedisRefreshLockService refreshLockService;
    private final KeycloakLogoutSuccessHandler logoutSuccessHandler;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    @Value("${app.security.additional-issuers:}")
    private String additionalIssuers;
    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;
    @Value("${app.security.frontend-base-url}")
    private String frontendBaseUrl;
    @Value("${app.security.refresh.clock-skew}")
    private Duration refreshClockSkew;
    @Value("${app.security.refresh.lock-ttl}")
    private Duration refreshLockTtl;
    @Value("${app.security.refresh.request-timeout}")
    private Duration refreshRequestTimeout;
    @Value("${server.reactive.session.cookie.name}")
    private String sessionCookieName;
    @Value("${server.reactive.session.cookie.secure}")
    private boolean secureSessionCookie;

    public SecurityConfig(
            KeycloakRoleConverter keycloakRoleConverter,
            KeycloakAuthoritiesExtractor authoritiesExtractor,
            RedisRefreshLockService refreshLockService,
            KeycloakLogoutSuccessHandler logoutSuccessHandler
    ) {
        this.keycloakRoleConverter = keycloakRoleConverter;
        this.authoritiesExtractor = authoritiesExtractor;
        this.refreshLockService = refreshLockService;
        this.logoutSuccessHandler = logoutSuccessHandler;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveJwtDecoder jwtDecoder,
            KeycloakOidcUserService oidcUserService,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
            ServerSecurityContextRepository securityContextRepository
    ) {
        CookieServerCsrfTokenRepository csrfTokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        csrfTokenRepository.setCookiePath("/");
        csrfTokenRepository.setSecure(secureSessionCookie);
        csrfTokenRepository.setCookieCustomizer(cookie -> cookie.sameSite("Lax"));

        OAuth2SessionRefreshWebFilter refreshWebFilter = new OAuth2SessionRefreshWebFilter(
                authorizedClientManager,
                authorizedClientRepository,
                jwtDecoder,
                authoritiesExtractor,
                refreshLockService,
                securityContextRepository,
                refreshClockSkew,
                refreshLockTtl,
                refreshRequestTimeout,
                sessionCookieName,
                secureSessionCookie
        );

        DelegatingServerLogoutHandler logoutHandler = new DelegatingServerLogoutHandler(
                new SecurityContextServerLogoutHandler(),
                new WebSessionServerLogoutHandler()
        );
        OidcAuthorizationCodeReactiveAuthenticationManager oidcAuthenticationManager =
                new OidcAuthorizationCodeReactiveAuthenticationManager(
                        new WebClientReactiveAuthorizationCodeTokenResponseClient(),
                        oidcUserService
                );

        return http
                .securityContextRepository(securityContextRepository)
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .requireCsrfProtectionMatcher(new SessionCsrfProtectionMatcher())
                )
                .cors(withDefaults())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/oauth2/**", "/login/**", "/error").permitAll()
                        .pathMatchers("/api/session", "/api/session/csrf").permitAll()
                        .pathMatchers("/api/v1/public/**").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/prometheus").permitAll()
                        .pathMatchers("/api/v1/admin/**").hasAnyRole("admin", "superadmin")
                        .pathMatchers("/api/v1/**").authenticated()
                        .anyExchange().denyAll()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((exchange, error) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler((exchange, error) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizedClientRepository(authorizedClientRepository)
                        .authenticationManager(oidcAuthenticationManager)
                        .authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler(
                                frontendBaseUrl + "/?authError=oauth2_login_failed"
                        ))
                        .authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler(frontendBaseUrl))
                )
                .oauth2Client(oauth2 -> oauth2
                        .authorizedClientRepository(authorizedClientRepository)
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                .jwtDecoder(jwtDecoder)
                        )
                )
                .logout(logout -> logout
                        .logoutUrl("/api/logout")
                        .logoutHandler(logoutHandler)
                        .logoutSuccessHandler(logoutSuccessHandler)
                )
                .addFilterBefore(refreshWebFilter, SecurityWebFiltersOrder.AUTHORIZATION)
                .build();
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    @Bean
    public ServerSecurityContextRepository securityContextRepository() {
        return new WebSessionServerSecurityContextRepository();
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken(configurer -> configurer.clockSkew(refreshClockSkew))
                        .build();

        DefaultReactiveOAuth2AuthorizedClientManager manager = new DefaultReactiveOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository
        );
        manager.setAuthorizedClientProvider(authorizedClientProvider);
        return manager;
    }

    @Bean
    public KeycloakOidcUserService keycloakOidcUserService(ReactiveJwtDecoder jwtDecoder) {
        return new KeycloakOidcUserService(jwtDecoder, authoritiesExtractor);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Request-Id", "X-XSRF-TOKEN"));
        config.setExposedHeaders(List.of("X-Request-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    @Profile("dev")
    public ReactiveJwtDecoder devJwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuerUri).build();
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator()));
        return jwtDecoder;
    }

    @Bean
    @Profile("!dev")
    public ReactiveJwtDecoder prodJwtDecoder() {
        Set<String> trustedIssuers = getTrustedIssuers();
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(buildJwkSetUri(issuerUri))
                .build();
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                trustedIssuerValidator(trustedIssuers)
        ));
        return jwtDecoder;
    }

    private ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(keycloakRoleConverter)
        );
        return converter;
    }

    private Set<String> getTrustedIssuers() {
        return Stream.concat(Stream.of(issuerUri), Stream.of(additionalIssuers.split(",")))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private OAuth2TokenValidator<Jwt> trustedIssuerValidator(Set<String> trustedIssuers) {
        return jwt -> trustedIssuers.contains(jwt.getIssuer() != null ? jwt.getIssuer().toString() : null)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                        "invalid_token",
                        "The token issuer is not trusted",
                        null
                ));
    }

    private String buildJwkSetUri(String issuer) {
        String normalizedIssuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return normalizedIssuer + "/protocol/openid-connect/certs";
    }
}
