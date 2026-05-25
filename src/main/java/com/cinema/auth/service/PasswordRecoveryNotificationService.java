package com.cinema.auth.service;

public interface PasswordRecoveryNotificationService {

    void sendPasswordRecoveryEmail(String email, String recoveryUrl);
}
