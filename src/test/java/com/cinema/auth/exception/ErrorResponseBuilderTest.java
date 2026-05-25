package com.cinema.auth.exception;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ErrorResponseBuilderTest {

    @Test
    void shouldBuildErrorResponse() {
        // Arrange
        Instant now = Instant.now();

        // Act
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(now)
                .status(401)
                .error("Unauthorized")
                .message("Credenciales invalidas")
                .path("/auth/login")
                .build();

        // Assert
        assertNotNull(response);
        assertEquals(401, response.getStatus());
        assertEquals("Unauthorized", response.getError());
        assertEquals("Credenciales invalidas", response.getMessage());
        assertEquals("/auth/login", response.getPath());
    }
}
