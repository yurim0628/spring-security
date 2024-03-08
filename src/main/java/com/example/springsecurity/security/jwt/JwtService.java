package com.example.springsecurity.security.jwt;

import com.example.springsecurity.common.redis.RedisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static com.example.springsecurity.security.SecurityConstants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtService {

    private final JwtProvider jwtProvider;
    private final RedisService redisService;

    public Token createToken(String email, String authorities, String uuid) {
        String accessToken = jwtProvider.generateAccessToken(email, authorities);
        log.info("access token generated for email: {}", email);

        String refreshToken = jwtProvider.generateRefreshToken(uuid);
        log.info("refresh token generated for uuid: {}", uuid);

        saveRefreshToken(uuid, email, refreshToken);

        return Token.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void saveRefreshToken(String uuid, String email, String refreshToken) {
        redisService.set(
                REFRESH_TOKEN_PREFIX + uuid,
                RefreshToken.from(email, refreshToken),
                REFRESH_TOKEN_EXPIRATION
        );
        log.info("refresh token saved for uuid: {}", uuid);
    }
}
