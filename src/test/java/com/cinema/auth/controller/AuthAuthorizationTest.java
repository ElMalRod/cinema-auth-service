package com.cinema.auth.controller;

import com.cinema.auth.config.SecurityConfig;
import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import com.cinema.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
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

    private static final UUID TARGET_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000401");
    private static final UUID PRINCIPAL_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000402");
    private static final String CLIENT_EMAIL = "client@test.com";
    private static final String CLIENT_TOKEN = "client-token";
    private static final String SYSTEM_ADMIN_TOKEN = "system-admin-token";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtProvider jwtProvider;

    @Test
    @WithMockUser(roles = "CLIENT")
    void should_ReturnUnauthorized_When_UserIsAuthenticatedButAuthorizationHeaderIsMissing() throws Exception {
        // Arrange

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", TARGET_USER_ID));

        // Assert
        action.andExpect(status().isUnauthorized());
    }

    @Test
    void should_ReturnUnauthorized_When_DeactivateRequestHasNoAuthenticationToken() throws Exception {
        // Arrange

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", TARGET_USER_ID));

        // Assert
        action.andExpect(status().isUnauthorized());
    }

    @Test
    void should_ReturnForbidden_When_RoleIsNotSystemAdmin() throws Exception {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(PRINCIPAL_USER_ID, CLIENT_EMAIL, UserRole.CLIENT);
        when(jwtProvider.parseToken(CLIENT_TOKEN)).thenReturn(Optional.of(principal));

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", TARGET_USER_ID)
                .header(AuthConstants.AUTHORIZATION_HEADER, AuthConstants.BEARER_PREFIX + CLIENT_TOKEN));

        // Assert
        action.andExpect(status().isForbidden());
    }

    @Test
    void should_AllowDeactivate_When_RoleIsSystemAdmin() throws Exception {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(PRINCIPAL_USER_ID, "admin@test.com", UserRole.SYSTEM_ADMIN);
        when(jwtProvider.parseToken(SYSTEM_ADMIN_TOKEN)).thenReturn(Optional.of(principal));

        // Act
        var action = mockMvc.perform(patch("/auth/deactivate/{id}", TARGET_USER_ID)
                .header(AuthConstants.AUTHORIZATION_HEADER, AuthConstants.BEARER_PREFIX + SYSTEM_ADMIN_TOKEN));

        // Assert
        action.andExpect(status().isNoContent());
        verify(authService).deactivateUser(TARGET_USER_ID);
    }
}
