package org.mota.jwtdemo.service.cache;

import org.springframework.security.core.context.SecurityContext;

import java.util.Optional;

public interface AccessTokensSecurityContextCache {

    void saveSecurityContext(String token, SecurityContext securityContext);

    boolean containsByToken(String token);

    void revokeToken(String token);

    boolean isRevoked(String token);

    Optional<SecurityContext> getContextByToken(String token);

}
