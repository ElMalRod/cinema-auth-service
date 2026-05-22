package com.cinema.auth.dto;

import com.cinema.auth.domain.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank String name,
        String phone,
        String companyName,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8, max = 100) String password,
        @NotNull UserRole role
) {
    public RegisterRequest(String name, String phone, String email, String password, UserRole role) {
        this(name, phone, null, email, password, role);
    }

    public RegisterRequest(String email, String password, UserRole role) {
        this("Usuario", null, null, email, password, role);
    }
}
