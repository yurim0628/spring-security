package com.example.springsecurity.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.CONFLICT;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    EMAIL_ALREADY_EXISTS(CONFLICT, "이미 사용 중인 이메일 입니다.");

    private final HttpStatus status;
    private final String message;
}
