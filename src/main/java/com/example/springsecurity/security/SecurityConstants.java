package com.example.springsecurity.security;

public class SecurityConstants {
    public static final String BEARER_TYPE = "Bearer";
    public static final String CLAIM_KEY = "auth";
    public static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30;
    public static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7;
}
