package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private static final String REQUEST_PATH = "/auth/me";
    private static final String HTTP_METHOD = "GET";
    private static final String BEARER_TOKEN = "valid-token";
    private static final String BEARER_HEADER_VALUE = AuthConstants.BEARER_PREFIX + BEARER_TOKEN;
    private static final String NON_BEARER_HEADER_VALUE = "Basic credentials";
    private static final String BLANK_BEARER_HEADER_VALUE = AuthConstants.BEARER_PREFIX + "   ";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000301");
    private static final String USER_EMAIL = "jwt-user@test.com";
    private static final String EXPECTED_AUTHORITY = "ROLE_CLIENT";

    @Mock
    private JwtProvider jwtProvider;

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() {
        jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtProvider);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void should_NotAuthenticate_When_AuthorizationHeaderIsMissing() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = buildRequest(null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // Act
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtProvider, never()).parseToken(anyString());
    }

    @Test
    void should_NotAuthenticate_When_AuthorizationHeaderIsNotBearer() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = buildRequest(NON_BEARER_HEADER_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // Act
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtProvider, never()).parseToken(anyString());
    }

    @Test
    void should_NotAuthenticate_When_BearerTokenIsBlank() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = buildRequest(BLANK_BEARER_HEADER_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // Act
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtProvider, never()).parseToken(anyString());
    }

    @Test
    void should_NotAuthenticate_When_ParsedPrincipalIsEmpty() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = buildRequest(BEARER_HEADER_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        when(jwtProvider.parseToken(BEARER_TOKEN)).thenReturn(Optional.empty());

        // Act
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void should_Authenticate_When_ValidPrincipalIsParsed() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = buildRequest(BEARER_HEADER_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        JwtPrincipal principal = new JwtPrincipal(USER_ID, USER_EMAIL, UserRole.CLIENT);
        when(jwtProvider.parseToken(BEARER_TOKEN)).thenReturn(Optional.of(principal));

        // Act
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Assert
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertEquals(USER_ID.toString(), authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream().anyMatch(authority -> EXPECTED_AUTHORITY.equals(authority.getAuthority())));
    }

    private MockHttpServletRequest buildRequest(String authorizationHeaderValue) {
        MockHttpServletRequest request = new MockHttpServletRequest(HTTP_METHOD, REQUEST_PATH);
        if (authorizationHeaderValue != null) {
            request.addHeader(AuthConstants.AUTHORIZATION_HEADER, authorizationHeaderValue);
        }
        return request;
    }
}
