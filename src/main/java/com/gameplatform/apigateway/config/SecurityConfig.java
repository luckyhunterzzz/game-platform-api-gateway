package com.gameplatform.apigateway.config;

import com.nimbusds.jwt.JWTParser;
import com.gameplatform.apigateway.security.KeycloakRoleConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Configuration class for WebFlux security in the API Gateway.
 * This class defines the security filter chain, access control rules for different endpoints
 * and integrates custom JWT role mapping for Keycloak
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final KeycloakRoleConverter keycloakRoleConverter;
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    @Value("${app.security.additional-issuers:}")
    private String additionalIssuers;
    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    /**
     * Configures the main security filter chain for the gateway.
     *
     * @param http the ServerHttpSecurity to configure.
     * @return the configurated ServerHttpSecurityChain.
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver
    ) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(withDefaults())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/api/v1/public/**").permitAll()
                        .pathMatchers("/actuator/health").permitAll()
                        .pathMatchers("/actuator/prometheus").permitAll()
                        .pathMatchers("/api/v1/admin/**").hasAnyRole("admin", "superadmin")
                        .pathMatchers("/api/v1/**").authenticated()
                        .anyExchange().denyAll()
                )
                .oauth2ResourceServer(oauth -> oauth.authenticationManagerResolver(authenticationManagerResolver))
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT","PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Request-Id"));
        config.setExposedHeaders(List.of("X-Request-Id"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * JWT Decoder for local development (dev profile).
     * It disables Issuer validation to avoid conflicts between localhost and docker network.
     */
    @Bean
    @Profile("dev")
    public ReactiveAuthenticationManagerResolver<ServerWebExchange> devAuthenticationManagerResolver() {
        ReactiveAuthenticationManager authenticationManager = buildDevAuthenticationManager(issuerUri);
        return exchange -> Mono.just(authenticationManager);
    }

    /**
     * Standard JWT Decoder for Production/Docker (all profiles except dev).
     * Provides strict validation for all JWT claims.
     */
    @Bean
    @Profile("!dev")
    public ReactiveAuthenticationManagerResolver<ServerWebExchange> prodAuthenticationManagerResolver() {
        Map<String, ReactiveAuthenticationManager> authenticationManagers = getTrustedIssuers().stream()
                .collect(Collectors.toMap(
                        issuer -> issuer,
                        this::buildProdAuthenticationManager,
                        (left, right) -> left,
                        java.util.LinkedHashMap::new
                ));
        ServerBearerTokenAuthenticationConverter bearerTokenConverter =
                new ServerBearerTokenAuthenticationConverter();

        return exchange -> bearerTokenConverter.convert(exchange)
                .cast(org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken.class)
                .map(org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken::getToken)
                .flatMap(token -> Mono.justOrEmpty(extractIssuer(token)))
                .flatMap(issuer -> Mono.justOrEmpty(authenticationManagers.get(issuer)));
    }

    private ReactiveAuthenticationManager buildDevAuthenticationManager(String issuer) {
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();

        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator()
        );

        jwtDecoder.setJwtValidator(validator);

        JwtReactiveAuthenticationManager authenticationManager = new JwtReactiveAuthenticationManager(jwtDecoder);
        authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        return authenticationManager;
    }

    private ReactiveAuthenticationManager buildProdAuthenticationManager(String issuer) {
        ReactiveJwtDecoder jwtDecoder = ReactiveJwtDecoders.fromIssuerLocation(issuer);
        JwtReactiveAuthenticationManager authenticationManager = new JwtReactiveAuthenticationManager(jwtDecoder);
        authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        return authenticationManager;
    }

    private ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(keycloakRoleConverter)
        );
        return jwtAuthenticationConverter;
    }

    private Set<String> getTrustedIssuers() {
        return Stream.concat(
                        Stream.of(issuerUri),
                        Stream.of(additionalIssuers.split(","))
                )
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private String extractIssuer(String token) {
        try {
            return JWTParser.parse(token).getJWTClaimsSet().getIssuer();
        } catch (ParseException exception) {
            return null;
        }
    }

}
