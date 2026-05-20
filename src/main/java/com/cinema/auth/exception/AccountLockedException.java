package com.cinema.auth.exception;

import com.cinema.auth.constants.AuthConstants;

public class AccountLockedException extends RuntimeException {

    public AccountLockedException() {
        super(AuthConstants.MESSAGE_ACCOUNT_LOCKED);
    }
}
