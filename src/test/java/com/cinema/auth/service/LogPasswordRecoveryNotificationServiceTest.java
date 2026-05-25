package com.cinema.auth.service;

import org.junit.jupiter.api.Test;

class LogPasswordRecoveryNotificationServiceTest {

    private static final String EMAIL = "client@test.com";
    private static final String RECOVERY_URL = "https://frontend/reset-password?token=abc";

    @Test
    void should_LogRecoveryNotificationWithoutThrowing_When_SendPasswordRecoveryEmailIsCalled() {
        // Arrange
        LogPasswordRecoveryNotificationService service = new LogPasswordRecoveryNotificationService();

        // Act
        service.sendPasswordRecoveryEmail(EMAIL, RECOVERY_URL);

        // Assert
    }
}
