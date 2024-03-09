package com.example.springsecurity.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

import static com.example.springsecurity.security.common.SecurityConstants.*;
import static io.jsonwebtoken.SignatureAlgorithm.HS256;

@Component
public class JwtProvider {

    private final Key key;

    public JwtProvider(@Value("${jwt.secret-key}") String secretKey) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    public String generateAccessToken(String email, String authorities) {
        Date expirationDate = calculateTokenExpiration(ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setSubject(email)
                .setExpiration(expirationDate)
                .claim(CLAIM_KEY, authorities)
                .signWith(key, HS256)
                .compact();
    }

    public String generateRefreshToken(String uuid) {
        Date expirationDate = calculateTokenExpiration(REFRESH_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setSubject(uuid)
                .setExpiration(expirationDate)
                .signWith(key, HS256)
                .compact();
    }

    public Date calculateTokenExpiration(Long expiration) {
        return new Date(System.currentTimeMillis() + expiration);
    }

    public String getSubject(String token) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        return getClaims(token).getSubject();
    }

    public String getAuthorities(String token) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        return getClaims(token).get(CLAIM_KEY, String.class);
    }

    public Long getExpiration(String token) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        return getClaims(token).getExpiration().getTime();
    }

    Claims getClaims(String token) throws ExpiredJwtException, SignatureException,
            MalformedJwtException, UnsupportedJwtException, IllegalArgumentException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
