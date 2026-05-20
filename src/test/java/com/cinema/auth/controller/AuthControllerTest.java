package com.cinema.auth.controller;

import com.cinema.auth.config.SecurityConfig;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.service.AuthService;
import com.cinema.auth.domain.UserRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @Test
    void shouldRegisterUser() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        RegisterRequest request = new RegisterRequest("admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
        LoginResponse response = new LoginResponse("token-value", userId, "admin@test.com", "SYSTEM_ADMIN");
        when(authService.register(any(RegisterRequest.class))).thenReturn(response);

        // Act
        var action = mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        // Assert
        action.andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("token-value"))
                .andExpect(jsonPath("$.email").value("admin@test.com"));
    }

    @Test
    void shouldLoginUser() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        LoginRequest request = new LoginRequest("client@test.com", "password123");
        LoginResponse response = new LoginResponse("token-login", userId, "client@test.com", "CLIENT");
        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        // Act
        var action = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        // Assert
        action.andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("token-login"))
                .andExpect(jsonPath("$.role").value("CLIENT"));
    }

    @Test
    void shouldReturnCurrentUser() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        MeResponse response = new MeResponse(userId, "client@test.com", "CLIENT", true);
        when(authService.getCurrentUser("Bearer token")).thenReturn(response);

        // Act
        var action = mockMvc.perform(get("/auth/me")
                .header("Authorization", "Bearer token"));

        // Assert
        action.andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("client@test.com"))
                .andExpect(jsonPath("$.active").value(true));
    }
}
