package com.cinema.auth.dto;

import com.cinema.auth.domain.UserRole;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminCreateUserRequestTest {

    private static final String EMAIL = "admin@test.com";
    private static final String PASSWORD = "password123";

    @Test
    void should_ApplyDefaultValues_When_UsingShortcutConstructor() {
        // Arrange

        // Act
        AdminCreateUserRequest request = new AdminCreateUserRequest(EMAIL, PASSWORD, UserRole.SYSTEM_ADMIN, true);

        // Assert
        assertEquals("Usuario", request.name());
        assertNull(request.phone());
        assertNull(request.companyName());
        assertEquals(EMAIL, request.email());
        assertEquals(PASSWORD, request.password());
        assertEquals(UserRole.SYSTEM_ADMIN, request.role());
        assertTrue(request.forcePasswordChange());
    }
}
