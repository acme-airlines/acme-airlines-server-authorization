package co.edu.uni.acme.ariline.server.authorization.dto;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

/**
 * Simple implementation of Authentication to represent the authenticating client.
 */
public class ClientAuthenticationTokenDto extends AbstractAuthenticationToken {

    private final String clientId;
    private String clientSecret; // This can be erased after authentication

    /**
     * Constructor for an unauthenticated token (without authorities).
     *
     * @param clientId     the client's identifier
     * @param clientSecret the client's password/secret
     */
    public ClientAuthenticationTokenDto(String clientId, String clientSecret) {
        super(null);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        setAuthenticated(false);
    }

    /**
     * Constructor for an already verified token, with authorities.
     *
     * @param clientId     the client's identifier
     * @param clientSecret the client's password/secret
     * @param authorities  the granted authorities
     */
    public ClientAuthenticationTokenDto(String clientId, String clientSecret, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        // Mark as authenticated
        super.setAuthenticated(true);
    }

    /**
     * Returns the credentials associated with the client.
     *
     * @return the client's secret
     */
    @Override
    public Object getCredentials() {
        return clientSecret;
    }

    /**
     * Returns the principal associated with the client.
     *
     * @return the client's identifier
     */
    @Override
    public Object getPrincipal() {
        return clientId;
    }

    /**
     * Prevents marking this token as authenticated after creation.
     *
     * @param isAuthenticated the desired authentication status
     * @throws IllegalArgumentException if an attempt is made to mark the token as authenticated
     */
    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot mark this token as trusted, use the constructor with authorities.");
        }
        super.setAuthenticated(false);
    }

    /**
     * Erases the credentials stored in this token.
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        clientSecret = null;
    }
}
