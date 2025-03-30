package co.edu.uni.acme.ariline.server.authorization.service;

import co.edu.uni.acme.ariline.server.authorization.dto.PasswordGrantAuthenticationTokenDto;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Converter for the "password" grant type authentication.
 * <p>
 * This component extracts the username, password, and client credentials from the HTTP request,
 * decodes the client credentials from the Authorization header (if provided), and creates an instance
 * of {@link PasswordGrantAuthenticationTokenDto}.
 * </p>
 */
@Log4j2
@Component
public class PasswordGrantAuthenticationConverterService implements AuthenticationConverter {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    /**
     * Converts the HttpServletRequest into a {@link PasswordGrantAuthenticationTokenDto} if the grant type is "password".
     *
     * @param request the HttpServletRequest containing the authentication parameters
     * @return an Authentication token or {@code null} if the grant type is not "password"
     * @throws IllegalArgumentException if the client credentials cannot be decoded or if no valid client authentication is provided
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            return null;
        }
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        RegisteredClient registeredClient = null;
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String base64Credentials = authHeader.substring("Basic ".length());
                byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(decodedBytes, StandardCharsets.UTF_8);
                // Credentials must be in the format "clientId:clientSecret"
                final String[] values = credentials.split(":", 2);
                if (values.length == 2) {
                    String clientId = values[0];
                    registeredClient = registeredClientRepository.findByClientId(clientId);
                }
            } catch (IllegalArgumentException e) {
                log.error(e.getMessage());
                throw new IllegalArgumentException("Error decoding client credentials", e);
            }
        }

        if (registeredClient == null) {
            throw new IllegalArgumentException("No valid client authentication provided");
        }

        return new PasswordGrantAuthenticationTokenDto(username, password, registeredClient);
    }
}
