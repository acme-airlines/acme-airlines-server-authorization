package co.edu.uni.acme.ariline.server.authorization.dto;

import java.util.Collections;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * <p>This version includes a convenience constructor to create the token from a
 * {@link RegisteredClient} without explicitly specifying the authentication method
 * or credentials (assumed {@code null}).</p>
 *
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 */
@Transient
public class OAuth2ClientAuthenticationTokenDto extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

    private final String clientId;

    private final RegisteredClient registeredClient;

    private final ClientAuthenticationMethod clientAuthenticationMethod;

    private final Object credentials;

    private final Map<String, Object> additionalParameters;

    /**
     * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
     *
     * @param clientId the client identifier
     * @param clientAuthenticationMethod the authentication method used by the client
     * @param credentials the client credentials
     * @param additionalParameters the additional parameters
     */
    public OAuth2ClientAuthenticationTokenDto(String clientId, ClientAuthenticationMethod clientAuthenticationMethod,
                                           @Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.hasText(clientId, "clientId cannot be empty");
        Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
        this.clientId = clientId;
        this.registeredClient = null;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.credentials = credentials;
        this.additionalParameters = Collections.unmodifiableMap(
                (additionalParameters != null) ? additionalParameters : Collections.emptyMap());
    }

    /**
     * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
     *
     * @param registeredClient the authenticated registered client
     * @param clientAuthenticationMethod the authentication method used by the client
     * @param credentials the client credentials
     */
    public OAuth2ClientAuthenticationTokenDto(RegisteredClient registeredClient,
                                           ClientAuthenticationMethod clientAuthenticationMethod, @Nullable Object credentials) {
        super(Collections.emptyList());
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
        this.clientId = registeredClient.getClientId();
        this.registeredClient = registeredClient;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.credentials = credentials;
        this.additionalParameters = Collections.emptyMap();
        setAuthenticated(true);
    }

    /**
     * Convenience constructor that creates an {@code OAuth2ClientAuthenticationToken}
     * from a {@link RegisteredClient} using the first defined authentication method
     * of the client (assuming one exists) and with no credentials.
     *
     * @param registeredClient the authenticated registered client
     */
    public OAuth2ClientAuthenticationTokenDto(RegisteredClient registeredClient) {
        this(registeredClient,
                // Uses the first defined authentication method; in a real scenario,
                // you might want to implement more robust logic.
                registeredClient.getClientAuthenticationMethods().iterator().next(),
                null);
        setAuthenticated(true);
    }

    /**
     * Returns the principal (client identifier).
     *
     * @return the client identifier
     */
    @Override
    public Object getPrincipal() {
        return this.clientId;
    }

    /**
     * Returns the credentials (client secret).
     *
     * @return the client credentials
     */
    @Nullable
    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    /**
     * Returns the authenticated {@link RegisteredClient}, or
     * {@code null} if not authenticated.
     *
     * @return the authenticated {@link RegisteredClient}, or {@code null} if not authenticated
     */
    @Nullable
    public RegisteredClient getRegisteredClient() {
        return this.registeredClient;
    }

    /**
     * Returns the {@link ClientAuthenticationMethod} used by the client.
     *
     * @return the client's authentication method
     */
    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return this.clientAuthenticationMethod;
    }

    /**
     * Returns the additional parameters.
     *
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
