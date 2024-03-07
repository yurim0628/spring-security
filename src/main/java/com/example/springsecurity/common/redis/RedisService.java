package com.example.springsecurity.common.redis;

import com.example.springsecurity.common.exception.CustomException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

import static com.example.springsecurity.common.exception.ErrorCode.JSON_PROCESSING_ERROR;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public void set(String key, Object data, Long expiration) {
        try {
            String value = objectMapper.writeValueAsString(data);
            redisTemplate.opsForValue().set(key, value, expiration, TimeUnit.MILLISECONDS);
        }
        catch (JsonProcessingException e) {
            log.error("Error occurred while processing JSON", e);
            throw new CustomException(JSON_PROCESSING_ERROR);
        }
    }
}
