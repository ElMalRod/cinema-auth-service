package com.cinema.auth.dto;

import com.cinema.auth.domain.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record AdminCreateUserRequest(
        @NotBlank String name,
        String phone,
        String companyName,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8, max = 100) String password,
        @NotNull UserRole role,
        boolean forcePasswordChange
) {
    public AdminCreateUserRequest(String email, String password, UserRole role, boolean forcePasswordChange) {
        this("Usuario", null, null, email, password, role, forcePasswordChange);
    }
}
