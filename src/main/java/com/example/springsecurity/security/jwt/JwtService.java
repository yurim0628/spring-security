package com.example.springsecurity.security.jwt;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.common.redis.RedisService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

import static com.example.springsecurity.common.exception.ErrorCode.INVALID_TOKEN;
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

    public void removeRefreshToken(String refreshToken) {
        try {
            String uuid = jwtProvider.getSubject(refreshToken);
            redisService.delete(REFRESH_TOKEN_PREFIX + uuid);
            log.info("refresh token removed for uuid: {}", uuid);
        } catch (ExpiredJwtException e) {
            log.warn("tried to remove refresh token for already expired token.");
        } catch (JwtException e) {
            throw new CustomException(INVALID_TOKEN);
        }
    }

    public void addBlackList(String accessToken) {
        try {
            long expirationTime = jwtProvider.getExpiration(accessToken);
            long validTime = expirationTime - Instant.now().toEpochMilli();
            redisService.set(
                    BLACKLIST_PREFIX + accessToken,
                    BLACKLIST_STATUS,
                    validTime
            );
            log.info("access token added to blacklist for accessToken: {}", accessToken);
        } catch (ExpiredJwtException e) {
            log.warn("tried to add access token for already expired token.");
        } catch (JwtException e) {
            throw new CustomException(INVALID_TOKEN);
        }
    }
}
