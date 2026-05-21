package com.cinema.auth.dto;

import java.util.UUID;

public record AuthUserSummaryResponse(
        UUID id,
        String email,
        String role,
        boolean active
) {
}