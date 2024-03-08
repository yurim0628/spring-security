package com.example.springsecurity.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    JSON_PROCESSING_ERROR(BAD_REQUEST, "JSON 처리 중 오류가 발생했습니다."),
    INVALID_REQUEST(BAD_REQUEST, "요청 형식이 올바르지 않습니다."),
    INVALID_CREDENTIALS(UNAUTHORIZED, "아이디 또는 비밀번호를 확인해주세요."),
    INVALID_TOKEN(UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    INTERNAL_AUTHENTICATION_ERROR(INTERNAL_SERVER_ERROR, "로그인 중에 내부 서버 오류가 발생했습니다."),
    UNKNOWN_ERROR(INTERNAL_SERVER_ERROR, "로그인 중에 알 수 없는 오류가 발생했습니다."),
    LOCKED_ACCOUNT(LOCKED, "계정이 잠겼습니다. 24시간 후에 다시 시도해주세요."),
    DISABLED_ACCOUNT(BAD_REQUEST,"이미 회원 탈퇴된 계정입니다."),
    EMAIL_ALREADY_EXISTS(CONFLICT, "이미 사용 중인 이메일 입니다.");

    private final HttpStatus status;
    private final String message;
}
