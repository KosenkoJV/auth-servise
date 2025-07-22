package com.example.auth.model;

import java.time.LocalDateTime;

public class Token {
    private final String value;
    private final String username;
    private final LocalDateTime expires;

    public Token(String value, String username, LocalDateTime expires) {
        this.value = value;
        this.username = username;
        this.expires = expires;
    }

    public String getValue() {
        return value;
    }

    public String getUsername() {
        return username;
    }

    public LocalDateTime getExpires() {
        return expires;
    }
}
