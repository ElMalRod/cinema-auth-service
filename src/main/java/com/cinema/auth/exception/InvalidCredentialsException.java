package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super(AuthConstants.MESSAGE_INVALID_CREDENTIALS);
    }
}
