/*package com.example.auth.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {

    private static final long REFRESH_TOKEN_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 дней

    private final Map<String, TokenInfo> refreshTokens = new ConcurrentHashMap<>();

    public String createRefreshToken(String username) {
        String token = UUID.randomUUID().toString();
        refreshTokens.put(token, new TokenInfo(username, Instant.now().plusMillis(REFRESH_TOKEN_EXPIRATION_MS)));
        return token;
    }


    public boolean isValid(String token) {
        TokenInfo info = refreshTokens.get(token);
        return info != null && info.expiration().isAfter(Instant.now());
    }

    public String getUsername(String token) {
        TokenInfo info = refreshTokens.get(token);
        return info != null ? info.username() : null;
    }

    public void revoke(String token) {
        refreshTokens.remove(token);
    }

    private record TokenInfo(String username, Instant expiration) {}
}
*/