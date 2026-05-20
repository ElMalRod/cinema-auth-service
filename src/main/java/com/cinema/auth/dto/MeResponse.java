package com.cinema.auth.dto;

import java.util.UUID;

public record MeResponse(
        UUID userId,
        String email,
        String role,
        boolean active
) {
}
