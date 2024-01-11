package org.mota.jwtdemo.auth;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mota.jwtdemo.service.cache.AccessTokensSecurityContextCache;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Repository;

import static java.util.Objects.isNull;
import static org.mota.jwtdemo.utils.SecurityUtils.extractAccessToken;

@Repository
@RequiredArgsConstructor
@Slf4j
public class TokenBasedSecurityContextRepository implements SecurityContextRepository {

    private final AccessTokensSecurityContextCache accessTokensSecurityContextCache;

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        var accessToken = extractAccessToken(requestResponseHolder.getRequest());
        if (isNull(accessToken) || accessTokensSecurityContextCache.isRevoked(accessToken)) {
            return SecurityContextHolder.createEmptyContext();
        }
        var securityContextOptional = accessTokensSecurityContextCache.getContextByToken(accessToken);

        return securityContextOptional.orElse(SecurityContextHolder.createEmptyContext());
    }


    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        var accessToken = (String) context.getAuthentication().getCredentials();
        if (isNull(accessToken)) {
            return;
        }
        accessTokensSecurityContextCache.saveSecurityContext(accessToken, context);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        var accessToken = extractAccessToken(request);
        if (isNull(accessToken)) {
            return false;
        }
        return accessTokensSecurityContextCache.containsByToken(accessToken);
    }

}
