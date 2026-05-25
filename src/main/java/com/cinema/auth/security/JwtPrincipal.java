package com.cinema.auth.security;

import com.cinema.auth.domain.UserRole;

import java.util.UUID;

public record JwtPrincipal(
        UUID userId,
        String email,
        UserRole role
) {
}
