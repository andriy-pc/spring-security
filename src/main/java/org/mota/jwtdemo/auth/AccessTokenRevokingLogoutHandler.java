package org.mota.jwtdemo.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.service.cache.AccessTokensSecurityContextCache;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import static java.util.Objects.isNull;
import static org.mota.jwtdemo.utils.SecurityUtils.extractAccessToken;
import static org.mota.jwtdemo.utils.ServletUtils.setResponseStatus;

@Component
@RequiredArgsConstructor
public class AccessTokenRevokingLogoutHandler implements LogoutHandler {

    private final AccessTokensSecurityContextCache accessTokensSecurityContextCache;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        var accessToken = extractAccessToken(request);
        if(isNull(accessToken)) {
            setResponseStatus(response, HttpStatus.BAD_REQUEST, "You have to include access token for proper logout. " +
                    "Please retry logout request with the Authorization header");
            return;
        }
        accessTokensSecurityContextCache.revokeToken(accessToken);
    }
}
