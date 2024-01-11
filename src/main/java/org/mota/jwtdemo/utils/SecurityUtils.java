package org.mota.jwtdemo.utils;

import jakarta.servlet.http.HttpServletRequest;

import static java.util.Objects.isNull;

public final class SecurityUtils {

    public static final String AUTHORIZATION_HEADER = "Authorization";


    private SecurityUtils() {

    }
    public static String extractAccessToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
        return isNull(authorizationHeader) ?
                null
                :
                extractAccessToken(authorizationHeader);
    }

    public static String extractAccessToken(String authorizationHeader) {
        return authorizationHeader.startsWith("Bearer ") ?
                authorizationHeader.substring("Bearer ".length())
                :
                authorizationHeader;
    }

}
