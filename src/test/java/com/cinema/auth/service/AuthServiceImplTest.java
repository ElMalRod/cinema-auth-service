package com.cinema.auth.service;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.dto.AdminCreateUserRequest;
import com.cinema.auth.dto.AdminCreateUserResponse;
import com.cinema.auth.dto.AuthUserSummaryResponse;
import com.cinema.auth.dto.ChangePasswordRequest;
import com.cinema.auth.dto.ForgotPasswordRequest;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.dto.ResetPasswordRequest;
import com.cinema.auth.exception.AccountLockedException;
import com.cinema.auth.exception.InvalidCredentialsException;
import com.cinema.auth.exception.InvalidRegistrationException;
import com.cinema.auth.exception.InvalidTokenException;
import com.cinema.auth.exception.UserAlreadyExistsException;
import com.cinema.auth.exception.UserNotFoundException;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;
    private static final int ONE_FAILED_ATTEMPT = 1;
    private static final int FOUR_FAILED_ATTEMPTS = 4;
    private static final int ZERO_FAILED_ATTEMPTS = 0;

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String INVALID_AUTH_HEADER = "Token invalid";
    private static final String TOKEN_VALUE = "token-value";
    private static final String LOGIN_TOKEN = "login-token";
    private static final String LOGOUT_TOKEN = "logout-token";
    private static final String CHANGE_PASSWORD_TOKEN = "change-password-token";
    private static final String RESET_TOKEN = "reset-token";

    private static final String CLIENT_NAME = "Client User";
    private static final String ADVERTISER_NAME = "Advertiser User";
    private static final String CINEMA_ADMIN_NAME = "Cinema Admin";
    private static final String DEFAULT_NAME = "Usuario";
    private static final String BLANK_NAME = "   ";
    private static final String CLIENT_PHONE = "5551234";
    private static final String ADVERTISER_PHONE = "5556789";
    private static final String CINEMA_ADMIN_PHONE = "5557777";
    private static final String BLANK_VALUE = "   ";
    private static final String COMPANY_NAME = "Cinema Group";
    private static final String CLIENT_EMAIL = "client@test.com";
    private static final String ADVERTISER_EMAIL = "advertiser@test.com";
    private static final String CINEMA_ADMIN_EMAIL = "cinema-admin@test.com";
    private static final String SYSTEM_ADMIN_EMAIL = "system-admin@test.com";
    private static final String EMAIL_WITH_SPACES = "  Client@Test.com  ";
    private static final String ENCODED_PASSWORD = "encoded-password";
    private static final String ENCODED_NEW_PASSWORD = "encoded-new-password";
    private static final String PASSWORD = "password123";
    private static final String NEW_PASSWORD = "new-password123";
    private static final String WRONG_PASSWORD = "wrong-password";

    private static final UUID CLIENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID ADVERTISER_ID = UUID.fromString("00000000-0000-0000-0000-000000000102");
    private static final UUID CINEMA_ADMIN_ID = UUID.fromString("00000000-0000-0000-0000-000000000103");
    private static final UUID SYSTEM_ADMIN_ID = UUID.fromString("00000000-0000-0000-0000-000000000104");
    private static final UUID UNKNOWN_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000999");

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 5, 24, 10, 0);

    @Mock
    private UserAuthRepository repository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private PasswordResetService passwordResetService;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private UserEventPublisher userEventPublisher;

    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                repository,
                passwordEncoder,
                jwtProvider,
                passwordResetService,
                tokenRevocationService,
                userEventPublisher,
                MAX_FAILED_ATTEMPTS,
                LOCK_MINUTES
        );
    }

    @Test
    void should_RegisterClientAndPublishDefaultName_When_PublicRegisterHasBlankNameAndPhone() {
        // Arrange
        RegisterRequest request = buildRegisterRequest(BLANK_NAME, BLANK_VALUE, CLIENT_EMAIL, UserRole.CLIENT);
        UserAuth savedUser = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(repository.existsByEmail(CLIENT_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);
        when(jwtProvider.generateToken(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT)).thenReturn(LOGIN_TOKEN);

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        assertEquals(LOGIN_TOKEN, response.token());
        verify(userEventPublisher).publishUserCreated(CLIENT_ID, DEFAULT_NAME, null);
    }

    @Test
    void should_RegisterAdvertiser_When_PublicRegisterRoleIsAdvertiser() {
        // Arrange
        RegisterRequest request = buildRegisterRequest(ADVERTISER_NAME, ADVERTISER_PHONE, ADVERTISER_EMAIL, UserRole.ADVERTISER);
        UserAuth savedUser = buildUser(ADVERTISER_ID, ADVERTISER_EMAIL, ENCODED_PASSWORD, UserRole.ADVERTISER, true);

        when(repository.existsByEmail(ADVERTISER_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);
        when(jwtProvider.generateToken(ADVERTISER_ID, ADVERTISER_EMAIL, UserRole.ADVERTISER)).thenReturn(LOGIN_TOKEN);

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        assertEquals(LOGIN_TOKEN, response.token());
        verify(userEventPublisher).publishAdvertiserCreated(ADVERTISER_ID, ADVERTISER_NAME, ADVERTISER_PHONE);
    }

    @Test
    void should_NotFailRegister_When_EventPublisherThrowsException() {
        // Arrange
        RegisterRequest request = buildRegisterRequest(CLIENT_NAME, CLIENT_PHONE, CLIENT_EMAIL, UserRole.CLIENT);
        UserAuth savedUser = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(repository.existsByEmail(CLIENT_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);
        when(jwtProvider.generateToken(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT)).thenReturn(LOGIN_TOKEN);
        doThrow(new RuntimeException("event-error")).when(userEventPublisher)
                .publishUserCreated(CLIENT_ID, CLIENT_NAME, CLIENT_PHONE);

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        assertEquals(LOGIN_TOKEN, response.token());
    }

    @Test
    void should_ThrowUserAlreadyExists_When_RegisteringExistingEmail() {
        // Arrange
        RegisterRequest request = buildRegisterRequest(CLIENT_NAME, CLIENT_PHONE, CLIENT_EMAIL, UserRole.CLIENT);
        when(repository.existsByEmail(CLIENT_EMAIL)).thenReturn(true);

        // Act
        UserAlreadyExistsException exception = assertThrows(UserAlreadyExistsException.class, () -> authService.register(request));

        // Assert
        assertEquals("El usuario ya existe", exception.getMessage());
        verify(repository, never()).save(any(UserAuth.class));
    }

    @Test
    void should_ThrowInvalidRegistration_When_PublicRoleIsSystemAdmin() {
        // Arrange
        RegisterRequest request = buildRegisterRequest(CLIENT_NAME, CLIENT_PHONE, SYSTEM_ADMIN_EMAIL, UserRole.SYSTEM_ADMIN);
        when(repository.existsByEmail(SYSTEM_ADMIN_EMAIL)).thenReturn(false);

        // Act
        InvalidRegistrationException exception = assertThrows(InvalidRegistrationException.class, () -> authService.register(request));

        // Assert
        assertEquals("Solo se permite registro publico para CLIENT y ADVERTISER", exception.getMessage());
        verify(repository, never()).save(any(UserAuth.class));
    }

    @Test
    void should_LoginAndClearFailedAttempts_When_CredentialsAreValid() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        user.setFailedLoginAttempts(FOUR_FAILED_ATTEMPTS);
        user.setLockedUntil(NOW.plusMinutes(LOCK_MINUTES));

        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(jwtProvider.generateToken(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT)).thenReturn(LOGIN_TOKEN);

        // Act
        LoginResponse response = authService.login(new LoginRequest(CLIENT_EMAIL, PASSWORD));

        // Assert
        assertEquals(LOGIN_TOKEN, response.token());
        assertEquals(ZERO_FAILED_ATTEMPTS, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        verify(repository).save(user);
    }

    @Test
    void should_ThrowInvalidCredentialsAndIncrementAttempts_When_PasswordDoesNotMatch() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(WRONG_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        // Act
        InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest(CLIENT_EMAIL, WRONG_PASSWORD))
        );

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
        assertEquals(ONE_FAILED_ATTEMPT, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        verify(repository).save(user);
    }

    @Test
    void should_LockAccount_When_MaxFailedAttemptsAreReached() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        user.setFailedLoginAttempts(FOUR_FAILED_ATTEMPTS);

        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(WRONG_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        // Act
        assertThrows(InvalidCredentialsException.class, () -> authService.login(new LoginRequest(CLIENT_EMAIL, WRONG_PASSWORD)));

        // Assert
        assertEquals(MAX_FAILED_ATTEMPTS, user.getFailedLoginAttempts());
        assertTrue(user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now().plusMinutes(LOCK_MINUTES - 1)));
    }

    @Test
    void should_ThrowAccountLocked_When_UserIsTemporarilyLocked() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));

        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.of(user));

        // Act
        AccountLockedException exception = assertThrows(AccountLockedException.class, () -> authService.login(new LoginRequest(CLIENT_EMAIL, PASSWORD)));

        // Assert
        assertEquals("Cuenta bloqueada temporalmente por intentos fallidos", exception.getMessage());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void should_ThrowInvalidCredentials_When_UserIsInactive() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, false);
        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.of(user));

        // Act
        InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest(CLIENT_EMAIL, PASSWORD))
        );

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void should_ThrowInvalidCredentials_When_UserEmailDoesNotExist() {
        // Arrange
        when(repository.findByEmail(CLIENT_EMAIL)).thenReturn(Optional.empty());

        // Act
        InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest(CLIENT_EMAIL, PASSWORD))
        );

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
    }

    @Test
    void should_ReturnCurrentUser_When_AuthorizationHeaderIsValid() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT);
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(jwtProvider.parseToken(TOKEN_VALUE)).thenReturn(Optional.of(principal));
        when(repository.findById(CLIENT_ID)).thenReturn(Optional.of(user));

        // Act
        MeResponse response = authService.getCurrentUser(BEARER_PREFIX + TOKEN_VALUE);

        // Assert
        assertEquals(CLIENT_ID, response.userId());
        assertEquals(CLIENT_EMAIL, response.email());
        assertEquals(UserRole.CLIENT.name(), response.role());
        assertTrue(response.active());
    }

    @Test
    void should_ThrowInvalidToken_When_AuthorizationHeaderHasInvalidPrefix() {
        // Arrange

        // Act
        InvalidTokenException exception = assertThrows(
                InvalidTokenException.class,
                () -> authService.getCurrentUser(INVALID_AUTH_HEADER)
        );

        // Assert
        assertEquals("Token invalido", exception.getMessage());
        verify(jwtProvider, never()).parseToken(anyString());
    }

    @Test
    void should_ThrowInvalidToken_When_PrincipalCannotBeParsed() {
        // Arrange
        when(jwtProvider.parseToken(TOKEN_VALUE)).thenReturn(Optional.empty());

        // Act
        InvalidTokenException exception = assertThrows(
                InvalidTokenException.class,
                () -> authService.getCurrentUser(BEARER_PREFIX + TOKEN_VALUE)
        );

        // Assert
        assertEquals("Token invalido", exception.getMessage());
    }

    @Test
    void should_ThrowUserNotFound_When_CurrentUserDoesNotExist() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(UNKNOWN_USER_ID, CLIENT_EMAIL, UserRole.CLIENT);
        when(jwtProvider.parseToken(TOKEN_VALUE)).thenReturn(Optional.of(principal));
        when(repository.findById(UNKNOWN_USER_ID)).thenReturn(Optional.empty());

        // Act
        UserNotFoundException exception = assertThrows(
                UserNotFoundException.class,
                () -> authService.getCurrentUser(BEARER_PREFIX + TOKEN_VALUE)
        );

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
    }

    @Test
    void should_RevokeToken_When_LogoutTokenIsValid() {
        // Arrange
        Instant expiration = Instant.parse("2026-05-24T20:10:30Z");
        JwtPrincipal principal = new JwtPrincipal(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT);

        when(jwtProvider.parseToken(LOGOUT_TOKEN)).thenReturn(Optional.of(principal));
        when(jwtProvider.extractExpiration(LOGOUT_TOKEN)).thenReturn(Optional.of(expiration));

        // Act
        authService.logout(BEARER_PREFIX + LOGOUT_TOKEN);

        // Assert
        verify(tokenRevocationService).revoke(LOGOUT_TOKEN, expiration);
    }

    @Test
    void should_ThrowInvalidToken_When_LogoutTokenCannotBeParsed() {
        // Arrange
        when(jwtProvider.parseToken(LOGOUT_TOKEN)).thenReturn(Optional.empty());

        // Act
        InvalidTokenException exception = assertThrows(
                InvalidTokenException.class,
                () -> authService.logout(BEARER_PREFIX + LOGOUT_TOKEN)
        );

        // Assert
        assertEquals("Token invalido", exception.getMessage());
        verify(tokenRevocationService, never()).revoke(anyString(), any(Instant.class));
    }

    @Test
    void should_ThrowInvalidToken_When_LogoutTokenHasNoExpiration() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT);
        when(jwtProvider.parseToken(LOGOUT_TOKEN)).thenReturn(Optional.of(principal));
        when(jwtProvider.extractExpiration(LOGOUT_TOKEN)).thenReturn(Optional.empty());

        // Act
        InvalidTokenException exception = assertThrows(
                InvalidTokenException.class,
                () -> authService.logout(BEARER_PREFIX + LOGOUT_TOKEN)
        );

        // Assert
        assertEquals("Token invalido", exception.getMessage());
    }

    @Test
    void should_RequestPasswordRecoveryWithNormalizedEmail_When_EmailContainsSpacesAndUppercase() {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest(EMAIL_WITH_SPACES);

        // Act
        authService.requestPasswordRecovery(request);

        // Assert
        verify(passwordResetService).request(CLIENT_EMAIL);
    }

    @Test
    void should_ResetPasswordWithTrimmedToken_When_TokenContainsSpaces() {
        // Arrange
        ResetPasswordRequest request = new ResetPasswordRequest(BLANK_VALUE + RESET_TOKEN + BLANK_VALUE, NEW_PASSWORD);

        // Act
        authService.resetPassword(request);

        // Assert
        verify(passwordResetService).reset(RESET_TOKEN, NEW_PASSWORD);
    }

    @Test
    void should_ChangePasswordAndDisableForceFlag_When_CurrentPasswordMatches() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT);
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        user.setRequiresPasswordChange(true);

        when(jwtProvider.parseToken(CHANGE_PASSWORD_TOKEN)).thenReturn(Optional.of(principal));
        when(repository.findById(CLIENT_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);

        // Act
        authService.changePassword(BEARER_PREFIX + CHANGE_PASSWORD_TOKEN, new ChangePasswordRequest(PASSWORD, NEW_PASSWORD));

        // Assert
        assertEquals(ENCODED_NEW_PASSWORD, user.getPasswordHash());
        assertFalse(user.isRequiresPasswordChange());
        verify(repository).save(user);
    }

    @Test
    void should_ThrowInvalidCredentials_When_CurrentPasswordDoesNotMatchDuringChangePassword() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(CLIENT_ID, CLIENT_EMAIL, UserRole.CLIENT);
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(jwtProvider.parseToken(CHANGE_PASSWORD_TOKEN)).thenReturn(Optional.of(principal));
        when(repository.findById(CLIENT_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(WRONG_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        // Act
        InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.changePassword(
                        BEARER_PREFIX + CHANGE_PASSWORD_TOKEN,
                        new ChangePasswordRequest(WRONG_PASSWORD, NEW_PASSWORD)
                )
        );

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
        verify(repository, never()).save(user);
    }

    @Test
    void should_ThrowUserNotFound_When_ChangingPasswordForUnknownUser() {
        // Arrange
        JwtPrincipal principal = new JwtPrincipal(UNKNOWN_USER_ID, CLIENT_EMAIL, UserRole.CLIENT);

        when(jwtProvider.parseToken(CHANGE_PASSWORD_TOKEN)).thenReturn(Optional.of(principal));
        when(repository.findById(UNKNOWN_USER_ID)).thenReturn(Optional.empty());

        // Act
        UserNotFoundException exception = assertThrows(
                UserNotFoundException.class,
                () -> authService.changePassword(
                        BEARER_PREFIX + CHANGE_PASSWORD_TOKEN,
                        new ChangePasswordRequest(PASSWORD, NEW_PASSWORD)
                )
        );

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
    }

    @Test
    void should_DeactivateUser_When_UserExists() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        when(repository.findById(CLIENT_ID)).thenReturn(Optional.of(user));

        // Act
        authService.deactivateUser(CLIENT_ID);

        // Assert
        assertFalse(user.isActive());
        verify(repository).save(user);
    }

    @Test
    void should_ThrowUserNotFound_When_DeactivatingUnknownUser() {
        // Arrange
        when(repository.findById(UNKNOWN_USER_ID)).thenReturn(Optional.empty());

        // Act
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> authService.deactivateUser(UNKNOWN_USER_ID));

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
        verify(repository, never()).save(any(UserAuth.class));
    }

    @Test
    void should_ActivateUserAndClearLockState_When_UserExists() {
        // Arrange
        UserAuth user = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, false);
        user.setFailedLoginAttempts(MAX_FAILED_ATTEMPTS);
        user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));

        when(repository.findById(CLIENT_ID)).thenReturn(Optional.of(user));

        // Act
        authService.activateUser(CLIENT_ID);

        // Assert
        assertTrue(user.isActive());
        assertEquals(ZERO_FAILED_ATTEMPTS, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        verify(repository).save(user);
    }

    @Test
    void should_ThrowUserNotFound_When_ActivatingUnknownUser() {
        // Arrange
        when(repository.findById(UNKNOWN_USER_ID)).thenReturn(Optional.empty());

        // Act
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> authService.activateUser(UNKNOWN_USER_ID));

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
    }

    @Test
    void should_ReturnSystemAdminExistence_When_CheckingExistsSystemAdmin() {
        // Arrange
        when(repository.existsByRoleAndActiveTrue(UserRole.SYSTEM_ADMIN)).thenReturn(true);

        // Act
        boolean existsSystemAdmin = authService.existsSystemAdmin();

        // Assert
        assertTrue(existsSystemAdmin);
    }

    @Test
    void should_CreateUserByAdminAndPublishCinemaAdmin_When_RoleIsCinemaAdmin() {
        // Arrange
        AdminCreateUserRequest request = buildAdminCreateRequest(CINEMA_ADMIN_NAME, CINEMA_ADMIN_PHONE, BLANK_VALUE, CINEMA_ADMIN_EMAIL, UserRole.CINEMA_ADMIN, true);
        UserAuth savedUser = buildUser(CINEMA_ADMIN_ID, CINEMA_ADMIN_EMAIL, ENCODED_PASSWORD, UserRole.CINEMA_ADMIN, true);
        savedUser.setRequiresPasswordChange(true);

        when(repository.existsByEmail(CINEMA_ADMIN_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);

        // Act
        AdminCreateUserResponse response = authService.createUserByAdmin(request);

        // Assert
        assertEquals(CINEMA_ADMIN_ID, response.id());
        assertTrue(response.requiresPasswordChange());
        verify(userEventPublisher).publishCinemaAdminCreated(CINEMA_ADMIN_ID, CINEMA_ADMIN_NAME, CINEMA_ADMIN_PHONE, null);
    }

    @Test
    void should_CreateUserByAdminAndPublishAdvertiser_When_RoleIsAdvertiser() {
        // Arrange
        AdminCreateUserRequest request = buildAdminCreateRequest(
                ADVERTISER_NAME,
                ADVERTISER_PHONE,
                COMPANY_NAME,
                ADVERTISER_EMAIL,
                UserRole.ADVERTISER,
                false
        );
        UserAuth savedUser = buildUser(ADVERTISER_ID, ADVERTISER_EMAIL, ENCODED_PASSWORD, UserRole.ADVERTISER, true);

        when(repository.existsByEmail(ADVERTISER_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);

        // Act
        authService.createUserByAdmin(request);

        // Assert
        verify(userEventPublisher).publishAdvertiserCreated(ADVERTISER_ID, ADVERTISER_NAME, ADVERTISER_PHONE);
    }

    @Test
    void should_CreateUserByAdminAndPublishUser_When_RoleIsClient() {
        // Arrange
        AdminCreateUserRequest request = buildAdminCreateRequest(CLIENT_NAME, CLIENT_PHONE, COMPANY_NAME, CLIENT_EMAIL, UserRole.CLIENT, false);
        UserAuth savedUser = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);

        when(repository.existsByEmail(CLIENT_EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(repository.save(any(UserAuth.class))).thenReturn(savedUser);

        // Act
        authService.createUserByAdmin(request);

        // Assert
        verify(userEventPublisher).publishUserCreated(CLIENT_ID, CLIENT_NAME, CLIENT_PHONE);
    }

    @Test
    void should_ThrowUserAlreadyExists_When_AdminCreatesDuplicatedEmail() {
        // Arrange
        AdminCreateUserRequest request = buildAdminCreateRequest(CLIENT_NAME, CLIENT_PHONE, COMPANY_NAME, CLIENT_EMAIL, UserRole.CLIENT, true);
        when(repository.existsByEmail(CLIENT_EMAIL)).thenReturn(true);

        // Act
        UserAlreadyExistsException exception = assertThrows(UserAlreadyExistsException.class, () -> authService.createUserByAdmin(request));

        // Assert
        assertEquals("El usuario ya existe", exception.getMessage());
    }

    @Test
    void should_ReturnMappedUserSummaries_When_ListUsersReturnsEntities() {
        // Arrange
        UserAuth firstUser = buildUser(CLIENT_ID, CLIENT_EMAIL, ENCODED_PASSWORD, UserRole.CLIENT, true);
        UserAuth secondUser = buildUser(SYSTEM_ADMIN_ID, SYSTEM_ADMIN_EMAIL, ENCODED_PASSWORD, UserRole.SYSTEM_ADMIN, true);
        when(repository.findAllByOrderByCreatedAtDesc()).thenReturn(List.of(firstUser, secondUser));

        // Act
        List<AuthUserSummaryResponse> users = authService.listUsers();

        // Assert
        assertEquals(2, users.size());
        assertEquals(CLIENT_ID, users.getFirst().id());
        assertEquals(SYSTEM_ADMIN_EMAIL, users.get(1).email());
    }

    @Test
    void should_ReturnEmptyList_When_NoUsersExist() {
        // Arrange
        when(repository.findAllByOrderByCreatedAtDesc()).thenReturn(List.of());

        // Act
        List<AuthUserSummaryResponse> users = authService.listUsers();

        // Assert
        assertTrue(users.isEmpty());
    }

    private RegisterRequest buildRegisterRequest(String name, String phone, String email, UserRole role) {
        return new RegisterRequest(name, phone, COMPANY_NAME, email, PASSWORD, role);
    }

    private AdminCreateUserRequest buildAdminCreateRequest(
            String name,
            String phone,
            String companyName,
            String email,
            UserRole role,
            boolean forcePasswordChange
    ) {
        return new AdminCreateUserRequest(name, phone, companyName, email, PASSWORD, role, forcePasswordChange);
    }

    private UserAuth buildUser(UUID userId, String email, String passwordHash, UserRole role, boolean active) {
        return UserAuth.builder()
                .id(userId)
                .email(email)
                .passwordHash(passwordHash)
                .role(role)
                .active(active)
                .requiresPasswordChange(false)
                .failedLoginAttempts(ZERO_FAILED_ATTEMPTS)
                .lockedUntil(null)
                .createdAt(NOW)
                .updatedAt(NOW)
                .build();
    }
}
