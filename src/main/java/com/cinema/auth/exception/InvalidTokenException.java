package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException() {
        super(AuthConstants.MESSAGE_INVALID_TOKEN);
    }
}
