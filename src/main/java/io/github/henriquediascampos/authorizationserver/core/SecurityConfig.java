package io.github.henriquediascampos.authorizationserver.core;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
// import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
// import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.henriquediascampos.authorizationserver.service.UserEntityService;
import io.github.henriquediascampos.authorizationserver.service.UserRepository;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http, UserEntityService userDetailsService)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .formLogin(withDefaults())
                .build();
    }

    @Bean
    public SecurityFilterChain authFilterChain(HttpSecurity http)
            throws Exception {

        http
            // .userDetailsService(userDetailsService)
                    // .csrf().disable()
                    // .authorizeRequests()
                    // .antMatchers("/h2-console/**", "/oauth2/**").permitAll()
                // .and()
                    .authorizeRequests()
                    .antMatchers("/user/**").hasRole("ADMIN")
                .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                // .and()
                //     .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    ;

        return http.formLogin(withDefaults())
                .build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient firstClient = RegisteredClient
                .withId("1")
                .clientId("clientid")
                .clientSecret(passwordEncoder.encode("clientsecret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/authorized")
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                // .redirectUri("http://localhost:8080/**")
                // .redirectUri("http://localhost:8080/login/oauth2/code/messaging-client-oidc")
                // .redirectUri("http://localhost:8080/login/oauth2/token/messaging-client-oidc")
                .scope("myuser:read")
                .scope("myuser:write")
                .scope("posts:write")
                .scope("ADMIN")
                .scope("USER")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(Arrays.asList(firstClient));
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(UserRepository userRepository) {
        return ( context -> {
            Authentication authentication = context.getPrincipal();
            if (authentication.getPrincipal() instanceof User) {
                final User user = User.class.cast(authentication.getPrincipal());

                final var userEntity = userRepository.findByEmail(user.getUsername()).orElseThrow();

                Set<String> authorites = new HashSet<>();
                for (GrantedAuthority authority : user.getAuthorities()) {
                    authorites.add(authority.toString());
                }

                context.getClaims().claim("user_id", userEntity.getId().toString());
                context.getClaims().claim("user_fullname", userEntity.getName());
                context.getClaims().claim("authorites", authorites);
            }
        });
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        var jwtAthConverter = new JwtAuthenticationConverter();
        jwtAthConverter.setJwtGrantedAuthoritiesConverter(
            jwt -> {
                List<String> roleAuthority = jwt.getClaimAsStringList("authorites");
                if (Objects.isNull(roleAuthority)) {
                    return Collections.emptyList();
                }

                JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();

                Collection<GrantedAuthority> scopesAuthority = scopes.convert(jwt);
                scopesAuthority.addAll(roleAuthority.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

                return scopesAuthority;
            }
        );

        return jwtAthConverter;
    }

    @Bean
    public ProviderSettings providerSettings(AuthProperties authProperties) {
        return ProviderSettings.builder()
            .issuer(authProperties.getProviderUri())
            .build();
    }

    @Bean
    public JWKSet jwkSet(AuthProperties authProperties) throws Exception {
        final var jksProperties = authProperties.getJks();
        final String jksPath = jksProperties.getPath();
        final InputStream inputStream = new ClassPathResource(jksPath).getInputStream();

        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, jksProperties.getStorepass().toCharArray());

        RSAKey rsaKey = RSAKey.load(keyStore,
                jksProperties.getAlias(),
                jksProperties.getKeypass().toCharArray());

        return new JWKSet(rsaKey);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwsEncoder(jwkSource);
    }
}