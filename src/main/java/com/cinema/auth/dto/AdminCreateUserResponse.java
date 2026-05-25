package com.cinema.auth.dto;

import java.util.UUID;

public record AdminCreateUserResponse(
        UUID id,
        String email,
        String role,
        boolean active,
        boolean requiresPasswordChange
) {
}