package com.cinema.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@ConditionalOnProperty(prefix = "notifications.brevo", name = "enabled", havingValue = "false", matchIfMissing = true)
public class LogPasswordRecoveryNotificationService implements PasswordRecoveryNotificationService {

    @Override
    public void sendPasswordRecoveryEmail(String email, String recoveryUrl) {
        log.info("Password recovery email simulated. email={}, url={}", email, recoveryUrl);
    }
}
