package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException() {
        super(AuthConstants.MESSAGE_USER_NOT_FOUND);
    }
}
