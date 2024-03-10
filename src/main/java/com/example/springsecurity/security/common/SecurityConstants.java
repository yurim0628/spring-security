package com.example.springsecurity.security.common;

public class SecurityConstants {
    public static final String REISSUE_URL_PATTERN = "/reissue";
    public static final String DEFAULT_HTTP_METHOD = "POST";

    public static final String EMAIL_ATTRIBUTE = "email";
    public static final String EXCEPTION_ATTRIBUTE = "exception";

    public static final String BLACKLIST_PREFIX = "black_list:";
    public static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    public static final String ACCOUNT_LOCKED_PREFIX = "locked_account:";

    public static final String BLACKLIST_STATUS = "logout";
    public static final String ACCOUNT_LOCKED_STATUS = "locked";

    public static final String BEARER_TYPE = "Bearer";
    public static final String CLAIM_KEY = "auth";
    public static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30;
    public static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7;

    public static final boolean ACCOUNT_ENABLED_STATUS = false;
    public static final boolean ACCOUNT_UNLOCKED_STATUS = true;
    public static final int MIN_FAILED_LOGIN_ATTEMPTS = 0;
    public static final int DEFAULT_LOGIN_ATTEMPT_INCREMENT = 1;
    public static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;
    public static final long ACCOUNT_LOCK_EXPIRATION = 1000 * 60 * 60 * 24;

    public static final String ACCESS_TOKEN_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int BEARER_PREFIX_LENGTH = BEARER_PREFIX.length();
}
