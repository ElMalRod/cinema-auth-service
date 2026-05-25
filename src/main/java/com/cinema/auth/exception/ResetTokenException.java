package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class ResetTokenException extends RuntimeException {

    public ResetTokenException() {
        super(AuthConstants.MESSAGE_RESET_TOKEN_INVALID);
    }
}
