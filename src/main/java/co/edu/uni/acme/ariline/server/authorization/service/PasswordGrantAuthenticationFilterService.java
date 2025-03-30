package co.edu.uni.acme.ariline.server.authorization.service;

import co.edu.uni.acme.ariline.server.authorization.dto.PasswordGrantAuthenticationTokenDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.stereotype.Component;

/**
 * Authentication filter for the password grant type.
 * <p>
 * This filter processes requests to "/oauth2/token" and handles the conversion and authentication
 * for the password grant. It also configures success and failure handlers to return JSON responses.
 * </p>
 */
@Component
public class PasswordGrantAuthenticationFilterService extends AbstractAuthenticationProcessingFilter {

    @Autowired
    private PasswordGrantAuthenticationConverterService converter;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * No-arg constructor with the default URL "/oauth2/token".
     * <p>
     * Configures a success handler that returns a 200 OK with a JSON response, and a failure handler
     * that returns a 401 Unauthorized with a JSON error message.
     * </p>
     */
    public PasswordGrantAuthenticationFilterService() {
        super("/oauth2/token");
        // Configure a success handler that returns a 200 OK and JSON response.
        setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Convert the Authentication to OAuth2AccessTokenAuthenticationToken.
            OAuth2AccessTokenAuthenticationToken tokenAuth = (OAuth2AccessTokenAuthenticationToken) authentication;

            // Extract the access token.
            OAuth2AccessToken accessToken = tokenAuth.getAccessToken();

            // Optional: extract additional data or customize the JSON response.
            Map<String, Object> tokenResponse = Map.of(
                    "accessToken", accessToken.getTokenValue(),
                    "issuedAt", Objects.requireNonNull(accessToken.getIssuedAt()),
                    "expiresAt", Objects.requireNonNull(accessToken.getExpiresAt()),
                    "scopes", accessToken.getScopes()
            );

            String jsonResponse = objectMapper.writeValueAsString(tokenResponse);
            response.getWriter().write(jsonResponse);
        });

        // Configure a failure handler that returns a JSON error message.
        setAuthenticationFailureHandler((request, response, exception) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\": \"" + exception.getMessage() + "\"}");
        });
    }

    /**
     * Sets the AuthenticationManager to be used by this filter.
     *
     * @param authenticationManager the AuthenticationManager instance
     */
    @Autowired
    public void setAuthManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    /**
     * Attempts to authenticate the incoming HTTP request.
     * <p>
     * Verifies that the grant type is "password", converts the request to an authentication token,
     * and then delegates authentication to the AuthenticationManager.
     * </p>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @return the authenticated token
     * @throws AuthenticationException if authentication fails
     * @throws IOException if an input or output exception occurs
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            throw new AuthenticationServiceException("Unsupported grant type");
        }
        PasswordGrantAuthenticationTokenDto authRequest =
                (PasswordGrantAuthenticationTokenDto) converter.convert(request);
        if (authRequest == null) {
            throw new AuthenticationServiceException("Could not obtain the authentication token");
        }
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Helper method to convert the token to JSON.
     * <p>
     * Constructs a simple JSON representation of the access token and its scopes.
     * Ideally, you would use a Jackson ObjectMapper for this purpose.
     * </p>
     *
     * @param tokenAuthentication the token authentication instance
     * @return a JSON string representing the access token
     */
    private String convertTokenToJson(OAuth2AccessTokenAuthenticationToken tokenAuthentication) {
        String tokenValue = tokenAuthentication.getAccessToken().getTokenValue();
        Set<String> scopes = tokenAuthentication.getAccessToken().getScopes();
        // A simple implementation (ideally use a Jackson ObjectMapper)
        return "{\"access_token\": \"" + tokenValue + "\", \"scopes\": " + scopes.toString() + "}";
    }
}
