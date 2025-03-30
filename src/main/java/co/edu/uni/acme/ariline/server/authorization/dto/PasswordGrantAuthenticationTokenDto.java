package co.edu.uni.acme.ariline.server.authorization.dto;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Authentication token for the "password" grant.
 * <p>
 * This token contains the username, password, and the RegisteredClient
 * that represents the authenticated client.
 * </p>
 */
public class PasswordGrantAuthenticationTokenDto extends AbstractAuthenticationToken {

    private final String username;
    private final String password;
    private final RegisteredClient registeredClient;

    /**
     * Constructor for an unauthenticated token.
     *
     * @param username         the username
     * @param password         the password
     * @param registeredClient the registered client (already obtained, for example, from the Authorization header)
     */
    public PasswordGrantAuthenticationTokenDto(String username, String password, RegisteredClient registeredClient) {
        super(null);
        this.username = username;
        this.password = password;
        this.registeredClient = registeredClient;
        setAuthenticated(false);
    }

    /**
     * Constructor for an already authenticated token.
     *
     * @param registeredClient the registered client
     * @param authorities      the granted authorities for the user
     */
    public PasswordGrantAuthenticationTokenDto(RegisteredClient registeredClient, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.username = null;
        this.password = null;
        this.registeredClient = registeredClient;
        setAuthenticated(true);
    }

    /**
     * Returns the username.
     *
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the password.
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Returns the registered client.
     *
     * @return the registered client
     */
    public RegisteredClient getRegisteredClient() {
        return registeredClient;
    }

    /**
     * Returns the credentials (password).
     *
     * @return the password
     */
    @Override
    public Object getCredentials() {
        return password;
    }

    /**
     * Returns the principal (username).
     *
     * @return the username
     */
    @Override
    public Object getPrincipal() {
        return username;
    }
}
