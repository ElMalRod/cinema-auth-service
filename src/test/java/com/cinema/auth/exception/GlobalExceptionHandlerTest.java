package com.cinema.auth.exception;

import com.cinema.auth.config.SecurityConfig;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import com.cinema.auth.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = com.cinema.auth.controller.AuthController.class)
@Import(SecurityConfig.class)
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtProvider jwtProvider;

    @Test
    void shouldReturn401ForInvalidCredentials() throws Exception {
        // Arrange
        LoginRequest request = new LoginRequest("client@test.com", "bad-pass");
        when(authService.login(any(LoginRequest.class))).thenThrow(new InvalidCredentialsException());

        // Act
        var action = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        // Assert
        action.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Credenciales invalidas"));
    }

    @Test
    void shouldReturn401ForInvalidToken() throws Exception {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), "client@test.com", UserRole.CLIENT);
        when(jwtProvider.parseToken("invalid")).thenReturn(Optional.of(principal));
        when(authService.getCurrentUser("Bearer invalid")).thenThrow(new InvalidTokenException());

        // Act
        var action = mockMvc.perform(get("/auth/me")
                .header("Authorization", "Bearer invalid"));

        // Assert
        action.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Token invalido"));
    }

    @Test
    void shouldReturn404ForUserNotFound() throws Exception {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), "client@test.com", UserRole.CLIENT);
        when(jwtProvider.parseToken("missing")).thenReturn(Optional.of(principal));
        when(authService.getCurrentUser("Bearer missing")).thenThrow(new UserNotFoundException());

        // Act
        var action = mockMvc.perform(get("/auth/me")
                .header("Authorization", "Bearer missing"));

        // Assert
        action.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message").value("Usuario no encontrado"));
    }

    @Test
    void shouldReturn409ForUserAlreadyExists() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest("admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
        when(authService.register(any(RegisterRequest.class))).thenThrow(new UserAlreadyExistsException());

        // Act
        var action = mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        // Assert
        action.andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("El usuario ya existe"));
    }

    @Test
    void shouldReturn400ForValidationErrors() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest("", "123", null);

        // Act
        var action = mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        // Assert
        action.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.path").value("/auth/register"));
    }
}
