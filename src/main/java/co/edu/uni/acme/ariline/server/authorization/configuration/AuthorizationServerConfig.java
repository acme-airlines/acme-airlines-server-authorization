package co.edu.uni.acme.ariline.server.authorization.configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import co.edu.uni.acme.aerolinea.commons.entity.PassengerEntity;
import co.edu.uni.acme.ariline.server.authorization.repository.PassengerRepository;
import co.edu.uni.acme.ariline.server.authorization.service.PasswordGrantAuthenticationFilterService;
import co.edu.uni.acme.ariline.server.authorization.service.PasswordGrantAuthenticationProviderService;
import lombok.RequiredArgsConstructor;

/**
 * Configuration class for the OAuth2 Authorization Server.
 * <p>
 * This class sets up the security filter chains, JWT encoding/decoding,
 * token generation, registered client repository, and user details service.
 * It also configures a custom password grant authentication filter and provider.
 * </p>
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {


    /**
     * Configures the security filter chain for the authorization server endpoints.
     * <p>
     * This method sets up the OAuth2 authorization server endpoints, registers a custom
     * authentication provider for the 'password' grant, and adds a custom authentication filter.
     * It also disables CSRF for these endpoints and configures exception handling to return
     * an HTTP 401 response for JSON requests.
     * </p>
     *
     * @param http the HttpSecurity to modify
     * @param userDetailsService the service used to load user-specific data
     * @param passwordEncoder the password encoder bean
     * @param tokenGenerator the token generator for generating OAuth2 access tokens
     * @param authenticationManager the authentication manager to be used by the custom filter
     * @return a SecurityFilterChain for the authorization server endpoints
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      UserDetailsService userDetailsService,
                                                                      PasswordEncoder passwordEncoder,
                                                                      OAuth2TokenGenerator<? extends OAuth2AccessToken> tokenGenerator,
                                                                      AuthenticationManager authenticationManager,
                                                                      AuthorizationServerSettings authorizationServerSettings) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Configure the authentication provider for the 'password' grant
        PasswordGrantAuthenticationProviderService passwordGrantProvider =
                new PasswordGrantAuthenticationProviderService(userDetailsService, passwordEncoder, tokenGenerator, authorizationServerSettings);
        http.authenticationProvider(passwordGrantProvider);

        // Define the custom password grant authentication filter and ensure it has the AuthenticationManager
        PasswordGrantAuthenticationFilterService passwordGrantFilter = passwordGrantAuthenticationFilter(authenticationManager);
        http.addFilterBefore(passwordGrantFilter, UsernamePasswordAuthenticationFilter.class);

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authServer -> authServer.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON)
                        )
                );

        return http.build();
    }


    /**
     * Configures the default security filter chain for non-authorization server endpoints.
     * <p>
     * This chain requires authentication for all requests, disables CSRF, and enables form login.
     * </p>
     *
     * @param http the HttpSecurity to configure
     * @return the default SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Creates a UserDetailsService that loads user details from a PassengerRepository.
     * <p>
     * The service fetches a PassengerEntity by email and converts it into a Spring Security
     * {@link User} object. If the user is not found, a {@link UsernameNotFoundException} is thrown.
     * </p>
     *
     * @param passengerRepository the repository used to retrieve passenger data
     * @return a UserDetailsService implementation
     */
    @Bean
    public UserDetailsService userDetailsService(PassengerRepository passengerRepository) {
        return email -> {
            PassengerEntity passenger = passengerRepository.findByEmailPassenger(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
            return User.builder()
                    .username(passenger.getEmailPassenger())
                    .password("{bcrypt}" + passenger.getHashPassword())
                    .roles("USER")
                    .build();
        };
    }

    /**
     * Configures an in-memory repository of registered OAuth2 clients.
     * <p>
     * This method sets up a single registered client with various grant types including
     * authorization code, refresh token, and a custom password grant type. It also configures
     * the client secret and token settings.
     * </p>
     *
     * @return a RegisteredClientRepository instance containing the registered client(s)
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oauthClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oauth-client")
                .clientSecret(passwordEncoder().encode("123456789"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .redirectUri("https://front.146.190.199.15.nip.io/oauth/oauth2/code/oauth-client")
                .redirectUri("https://front.146.190.199.15.nip.io/oauth/v1/public/auth/authorized")
                .postLogoutRedirectUri("https://front.146.190.199.15.nip.io/oauth/logout")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                // Configure token as SELF_CONTAINED (JWT)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(oauthClient);
    }

    /**
     * Provides a PasswordEncoder bean that delegates to various encoders.
     *
     * @return a PasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Generates an RSA KeyPair for signing JWTs.
     * <p>
     * This private helper method creates an RSA key pair using a 2048-bit key size.
     * </p>
     *
     * @return a generated RSA KeyPair
     */
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Configures the JwtEncoder bean using a provided JWKSource.
     *
     * @param jwkSource the JWKSource to be used by the encoder
     * @return a JwtEncoder instance
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Configures the JwtDecoder bean using a provided JWKSource.
     *
     * @param jwkSource the JWKSource to be used by the decoder
     * @return a JwtDecoder instance
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Configures the settings for the authorization server.
     *
     * @return an AuthorizationServerSettings instance with default settings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://front.146.190.199.15.nip.io/authorization")
                .build();
    }

    /**
     * Configures the token generator using a JwtEncoder.
     * <p>
     * This bean uses {@link JwtGenerator} to generate self-contained JWT access tokens.
     * </p>
     *
     * @param jwtEncoder the JwtEncoder to sign tokens
     * @return an OAuth2TokenGenerator instance
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder,
                                                  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return jwtGenerator;
    }

    /**
     * Configures the JWKSource bean based on an RSA key pair.
     * <p>
     * This method generates an RSA key pair, creates an RSAKey with a unique key ID,
     * and then builds an ImmutableJWKSet to be used for JWT encoding and decoding.
     * </p>
     *
     * @return a JWKSource instance containing the RSA key set
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Exposes the AuthenticationManager bean using the provided AuthenticationConfiguration.
     *
     * @param authConfig the AuthenticationConfiguration used to retrieve the AuthenticationManager
     * @return an AuthenticationManager instance
     * @throws Exception if an error occurs while retrieving the AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Creates and configures the custom PasswordGrantAuthenticationFilter bean.
     * <p>
     * This filter is used to handle authentication requests using the custom password grant type.
     * </p>
     *
     * @param authenticationManager the AuthenticationManager to set on the filter
     * @return a configured PasswordGrantAuthenticationFilter instance
     */
    @Bean
    public PasswordGrantAuthenticationFilterService passwordGrantAuthenticationFilter(AuthenticationManager authenticationManager) {
        PasswordGrantAuthenticationFilterService filter = new PasswordGrantAuthenticationFilterService();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(AuthorizationServerSettings authorizationServerSettings) {
        return context -> {
            // Solo personalizamos el token de acceso (access token)
            System.out.println("init");
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                String issuer = authorizationServerSettings.getIssuer();
                context.getClaims().issuer(authorizationServerSettings.getIssuer());
                System.out.println("JWT Customizer: Agregando issuer " + issuer);
            }
        };
    }

}
