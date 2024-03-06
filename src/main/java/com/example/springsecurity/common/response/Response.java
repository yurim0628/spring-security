package com.example.springsecurity.common.response;

public record Response<T>(
        String status,
        T data,
        String message
) {
    private static final String STATUS_SUCCESS = "SUCCESS";
    private static final String STATUS_FAIL = "FAIL";
    private static final String ERROR_STATUS = "ERROR";

    public static <T> Response<T> success() {
        return new Response<>(STATUS_SUCCESS, null, null);
    }

    public static <T> Response<T> success(T data) {
        return new Response<>(STATUS_SUCCESS, data, null);
    }

    public static <T> Response<T> fail(String message) {
        return new Response<>(STATUS_FAIL, null, message);
    }
}
