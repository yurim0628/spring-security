package com.example.springsecurity.security.authentication;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.common.redis.RedisService;
import com.example.springsecurity.security.PrincipalDetailsService;
import com.example.springsecurity.security.reissue.ReissueResponse;
import com.example.springsecurity.security.RefreshToken;
import com.example.springsecurity.security.Token;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Instant;

import static com.example.springsecurity.common.exception.ErrorCode.INVALID_TOKEN;
import static com.example.springsecurity.security.common.SecurityConstants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenAuthenticationService {

    private final TokenAuthenticationProvider tokenAuthenticationProvider;
    private final RedisService redisService;
    private final PrincipalDetailsService principalDetailsService;

    public Token createToken(String email, String authorities, String uuid) {
        String accessToken = tokenAuthenticationProvider.generateAccessToken(email, authorities);
        log.info("access token generated for email: {}", email);

        String refreshToken = tokenAuthenticationProvider.generateRefreshToken(uuid);
        log.info("refresh token generated for uuid: {}", uuid);

        saveRefreshToken(uuid, email, authorities, refreshToken);

        return Token.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void saveRefreshToken(String uuid, String email, String authorities, String refreshToken) {
        redisService.set(
                REFRESH_TOKEN_PREFIX + uuid,
                RefreshToken.from(uuid, email, authorities, refreshToken),
                REFRESH_TOKEN_EXPIRATION
        );
        log.info("refresh token saved for uuid: {}", uuid);
    }

    public void removeRefreshToken(String refreshToken) {
        try {
            String uuid = tokenAuthenticationProvider.getSubject(refreshToken);
            redisService.delete(REFRESH_TOKEN_PREFIX + uuid);
            log.info("refresh token removed for uuid: {}", uuid);
        } catch (ExpiredJwtException e) {
            log.warn("tried to remove refresh token for already expired token.");
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new CustomException(INVALID_TOKEN);
        }
    }

    public void addBlackList(String accessToken) {
        try {
            long expirationTime = tokenAuthenticationProvider.getExpiration(accessToken);
            long validTime = expirationTime - Instant.now().toEpochMilli();
            redisService.set(
                    BLACKLIST_PREFIX + accessToken,
                    BLACKLIST_STATUS,
                    validTime
            );
            log.info("access token added to blacklist for accessToken: {}", accessToken);
        } catch (ExpiredJwtException e) {
            log.warn("tried to add access token for already expired token.");
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new CustomException(INVALID_TOKEN);
        }
    }

    public boolean isBlackListToken(String accessToken) {
        return redisService.get(REFRESH_TOKEN_PREFIX + accessToken, String.class).isPresent();
    }

    public RefreshToken validateRefreshToken(String refreshToken) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        String uuid = tokenAuthenticationProvider.getSubject(refreshToken);
        RefreshToken redisRefreshToken = redisService.get(
                    REFRESH_TOKEN_PREFIX + uuid,
                    RefreshToken.class
        ).orElseThrow(() -> new CustomException(INVALID_TOKEN));

        if (!refreshToken.equals(redisRefreshToken.refreshToken())) {
            throw new CustomException(INVALID_TOKEN);
        }

        return redisRefreshToken;
    }

    public ReissueResponse reissueToken(RefreshToken redisRefreshToken) {
        String uuid = redisRefreshToken.uuid();
        String email = redisRefreshToken.email();
        String authorities = redisRefreshToken.authorities();
        Token reissuedToken = createToken(email, authorities, uuid);

        String reissuedRefreshToken = reissuedToken.refreshToken();
        saveRefreshToken(uuid, email, authorities, reissuedRefreshToken);

        return ReissueResponse.from(reissuedToken);
    }

    public Authentication getAuthentication(String accessToken) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        String email = tokenAuthenticationProvider.getSubject(accessToken);
        UserDetails userDetails = principalDetailsService.loadUserByUsername(email);

        return new UsernamePasswordAuthenticationToken(
                userDetails,
                "",
                userDetails.getAuthorities()
        );
    }
}
