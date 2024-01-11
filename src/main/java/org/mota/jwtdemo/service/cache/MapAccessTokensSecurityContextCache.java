package org.mota.jwtdemo.service.cache;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.util.Pair;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.isNull;

@Component
public class MapAccessTokensSecurityContextCache implements AccessTokensSecurityContextCache {

    public static final boolean TOKEN_IS_ACTIVE = true;
    public static final boolean TOKEN_IS_REVOKED = !TOKEN_IS_ACTIVE;
    private final Map<String, Pair<SecurityContext, Boolean>> cache = new HashMap<>();


    @Override
    public void saveSecurityContext(String token, SecurityContext securityContext) {
        String tokenSha256hex = DigestUtils.sha256Hex(token);
        cache.put(tokenSha256hex, Pair.of(securityContext, TOKEN_IS_ACTIVE));
    }

    @Override
    public boolean containsByToken(String token) {
        var contextRevokeFlagPairOptional = getContextRevokeFlagPair(token);
        return contextRevokeFlagPairOptional
                .filter(securityContextBooleanPair -> !isRevoked(securityContextBooleanPair))
                .isPresent();
    }

    @Override
    public void revokeToken(String token) {
        if (isNull(token)) {
            return;
        }
        var contextRevokeFlagPairOptional = getContextRevokeFlagPair(token);
        contextRevokeFlagPairOptional
                .ifPresent(securityContextBooleanPair ->
                        cache.put(token, Pair.of(securityContextBooleanPair.getFirst(), TOKEN_IS_REVOKED)));
    }

    @Override
    public boolean isRevoked(String token) {
        var contextRevokeFlagPairOptional = getContextRevokeFlagPair(token);
        return contextRevokeFlagPairOptional
                .map(this::isRevoked)
                .orElse(true);
    }

    private boolean isRevoked(Pair<SecurityContext, Boolean> contextRevokeFlagPair) {
        return !contextRevokeFlagPair.getSecond();
    }

    @Override
    public Optional<SecurityContext> getContextByToken(String token) {
        var contextRevokeFlagPairOptional = getContextRevokeFlagPair(token);
        return contextRevokeFlagPairOptional.map(Pair::getFirst);
    }

    private Optional<Pair<SecurityContext, Boolean>> getContextRevokeFlagPair(String token) {
        String tokenSha256hex = DigestUtils.sha256Hex(token);
        return Optional.ofNullable(cache.get(tokenSha256hex));
    }

}
