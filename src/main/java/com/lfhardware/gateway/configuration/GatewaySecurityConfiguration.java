package com.lfhardware.gateway.configuration;

import com.lfhardware.filter.TestWebFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.route.builder.UriSpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler;
import org.springframework.security.web.server.csrf.*;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfiguration {

    @Autowired
    private ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

    private final String[] allowedPaths = {"/api/v1/payments/webhook"};

    private final String[] allowedGETPaths = {"/api/v1/service-providers"};

    @Bean
    SecurityWebFilterChain securityFilterChain(ServerHttpSecurity httpSecurity) {
        XorServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();
        // Use only the handle() method of XorServerCsrfTokenRequestAttributeHandler and the
        // default implementation of resolveCsrfTokenValue() from ServerCsrfTokenRequestHandler
        ServerCsrfTokenRequestHandler requestHandler = delegate::handle;
        return httpSecurity
                .cors(corsSpec -> corsSpec.configurationSource(corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable
                        //.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        //.requireCsrfProtectionMatcher(new NegatedServerWebExchangeMatcher(exchange -> ServerWebExchangeMatchers.pathMatchers("/api/v1/payments/webhook").matches(exchange)))
                        //.csrfTokenRequestHandler(requestHandler)
                )
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
//                        .pathMatchers("/api/**")
//                        .authenticated()
////                        .pathMatchers(allowedPaths)
////                        .permitAll()
//                        .pathMatchers(HttpMethod.GET, "/api/v1/service-providers", "/api/v1/services").permitAll()
                        .anyExchange().permitAll())
                //.addFilterAfter(CsrfWebFilter, new TestWebFilter())
                .oauth2Login(oAuth2LoginSpec -> oAuth2LoginSpec.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("http://localhost:8090")))
                .logout(logoutSpec -> logoutSpec.logoutSuccessHandler(new AngularLogoutSucessHandler(reactiveClientRegistrationRepository, "http://localhost:8090"))
                )
//                .oidcLogout((logoutSpec)-> logoutSpec
//                        .backChannel(Customizer.withDefaults()))
//                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                //.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec.jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(grantedAuthoritiesExtractor())))
               // .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/login/oauth2")))
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setExposedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {
                /* Ensures the token is subscribed to. */
            }).then(chain.filter(exchange));
        };
    }

//    @Bean
//    public RouteLocator theRoutes(RouteLocatorBuilder builder) {
//        return builder.routes()
//                .route("auth", r ->
//                        r.path("/realms/**")
//                                .filters(f -> f.rewriteResponseHeader("Referrer-Policy", "no-referrer", "same-origin"))
//                                .uri("https://localhost:8080"))
//                .build();
//    }


//    @Bean
//    public RouteLocator myRoutes(RouteLocatorBuilder builder, Function<GatewayFilterSpec, UriSpec> brutalCorsFilters) {
//        return builder
//                .routes()
//                .route(p -> p.path("/api/**").filters(brutalCorsFilters).uri("https://localhost:8081"))
//                .build();
//    }
//
//    @Bean
//    Function<GatewayFilterSpec, UriSpec> brutalCorsFilters() {
//        return f -> f
//                .setResponseHeader("Access-Control-Allow-Origin", "*")
//                .setResponseHeader("Access-Control-Allow-Methods", "*")
//                .setResponseHeader("Access-Control-Expose-Headers", "*");
//    }
//    ServerAuthenticationEntryPoint browserRedirectEntryPoint() {
//        MediaTypeServerWebExchangeMatcher browserMatcher =
//                new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
//        // This avoids wildcard "Accept: */*" headers causing greedy browser match
//        browserMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
//
//        System.out.println("Redirect");
//        ServerAuthenticationEntryPoint redirect =
//                new RedirectServerAuthenticationEntryPoint("http://localhost:8090/oauth/login/keycloak");
//        return new DelegatingServerAuthenticationEntryPoint(new DelegatingServerAuthenticationEntryPoint.DelegateEntry(browserMatcher, redirect));
//    }

    static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
        private final OidcClientInitiatedServerLogoutSuccessHandler delegate;

        public AngularLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
            this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
            this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
        }

        @Override
        public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
            return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
                exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
            }));
        }

    }
    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(){
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(reactiveClientRegistrationRepository);
        oidcLogoutSuccessHandler.setLogoutSuccessUrl(URI.create("/api/oauth2/logout"));
//        oidcLogoutSuccessHandler.onLogoutSuccess(new WebFilterExchange());
//            return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
//                exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
//            }));
       // oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8090");
        return oidcLogoutSuccessHandler;
    }

//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowCredentials(true);
//        configuration.setAllowedOriginPatterns(List.of("*"));
//        configuration.setAllowedMethods(List.of("*"));
//        configuration.setAllowedHeaders(List.of("*"));
//        configuration.addExposedHeader(HttpHeaders.CONTENT_DISPOSITION);
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//
//    }

//    @Bean
//    public RouterFunction<ServerResponse> routerFunction(){
//        return RouterFunctions.resources("/**", new ClassPathResource("static/browser/"));
//    }


}
