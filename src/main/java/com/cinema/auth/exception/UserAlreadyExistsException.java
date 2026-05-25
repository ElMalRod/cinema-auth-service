package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException() {
        super(AuthConstants.MESSAGE_USER_EXISTS);
    }
}
