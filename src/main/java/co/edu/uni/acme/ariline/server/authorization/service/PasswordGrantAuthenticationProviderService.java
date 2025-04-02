package co.edu.uni.acme.ariline.server.authorization.service;

import co.edu.uni.acme.ariline.server.authorization.dto.DefaultAuthorizationServerContextDto;
import co.edu.uni.acme.ariline.server.authorization.dto.OAuth2ClientAuthenticationTokenDto;
import co.edu.uni.acme.ariline.server.authorization.dto.PasswordGrantAuthenticationTokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;

import java.util.Set;

/**
 * Authentication provider for the password grant.
 * <p>
 * This provider validates the user's credentials and generates a self-contained JWT access token.
 * It wraps the authenticated user details and returns an OAuth2AccessTokenAuthenticationToken.
 * </p>
 */
@Log4j2
@Component
@RequiredArgsConstructor
public class PasswordGrantAuthenticationProviderService implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2TokenGenerator<? extends OAuth2AccessToken> tokenGenerator;
    private final AuthorizationServerSettings authorizationServerSettings; // Inyectado

    /**
     * Authenticates the password grant request.
     *
     * @param authentication the authentication request token containing username, password, and client info
     * @return an authenticated token with the generated access token
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationTokenDto authToken = (PasswordGrantAuthenticationTokenDto) authentication;
        String username = authToken.getUsername();
        String password = authToken.getPassword();

        // Validate the user's credentials
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        RegisteredClient registeredClient = authToken.getRegisteredClient();
        if (registeredClient == null) {
            throw new BadCredentialsException("No authenticated client was found");
        }

        // Define the authorized scopes
        Set<String> scopes = Set.of("openid", "profile", "read", "write");

        // Wrap the UserDetails in an already authenticated Authentication token
        Authentication userPrincipal = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        // Build the context for token generation
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationGrant(authToken)
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationServerContext(new DefaultAuthorizationServerContextDto(
                        authorizationServerSettings.getIssuer(),
                        authorizationServerSettings))
                .build();

        // Generate the token (a Jwt is expected since JwtGenerator is used)
        Object generatedToken = tokenGenerator.generate(tokenContext);
        if (!(generatedToken instanceof Jwt)) {
            throw new IllegalStateException("The token generator was unable to generate an access token");
        }
        Jwt jwt = (Jwt) generatedToken;

        // Convert the Jwt to an OAuth2AccessToken (self-contained JWT)
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                jwt.getIssuedAt(),
                jwt.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );

        // Create the authentication token for the client (using the RegisteredClient)
        OAuth2ClientAuthenticationTokenDto clientPrincipal = new OAuth2ClientAuthenticationTokenDto(registeredClient);

        // Return the access token along with the authenticated client information
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    /**
     * Indicates whether this provider supports the indicated authentication type.
     *
     * @param authentication the class of the authentication object
     * @return true if the provider supports PasswordGrantAuthenticationTokenDto; false otherwise
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationTokenDto.class.isAssignableFrom(authentication);
    }
}
