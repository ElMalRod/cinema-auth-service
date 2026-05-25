package com.cinema.auth.dto;

import java.util.UUID;

public record LoginResponse(
        String token,
        UUID userId,
        String email,
        String role
) {
}
