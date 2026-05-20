package com.cinema.auth.controller;

import com.cinema.auth.config.SecurityConfig;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import com.cinema.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtProvider jwtProvider;

    @Test
    void shouldReturn401WhenDeactivateHasNoToken() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", userId));

        // Assert
        action.andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturn403WhenRoleIsNotSystemAdmin() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), "client@test.com", UserRole.CLIENT);
        when(jwtProvider.parseToken("client-token")).thenReturn(Optional.of(principal));

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", userId)
                .header("Authorization", "Bearer client-token"));

        // Assert
        action.andExpect(status().isForbidden());
    }

    @Test
    void shouldAllowSystemAdminToDeactivateUser() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), "admin@test.com", UserRole.SYSTEM_ADMIN);
        when(jwtProvider.parseToken("admin-token")).thenReturn(Optional.of(principal));

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", userId)
                .header("Authorization", "Bearer admin-token"));

        // Assert
        action.andExpect(status().isNoContent());
        verify(authService).deactivateUser(userId);
    }
}
