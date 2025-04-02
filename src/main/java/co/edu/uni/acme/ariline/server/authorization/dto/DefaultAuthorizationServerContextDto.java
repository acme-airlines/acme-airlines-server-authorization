package co.edu.uni.acme.ariline.server.authorization.dto;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

public class DefaultAuthorizationServerContextDto implements AuthorizationServerContext {

    private final String issuer;
    private final AuthorizationServerSettings settings;

    public DefaultAuthorizationServerContextDto(String issuer, AuthorizationServerSettings settings) {
        this.issuer = issuer;
        this.settings = settings;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        return settings;
    }
}
