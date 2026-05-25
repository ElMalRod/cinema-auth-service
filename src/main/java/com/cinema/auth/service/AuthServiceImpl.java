package com.cinema.auth.service;

import com.cinema.auth.constants.AuthConstants;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserAuthRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final PasswordResetService passwordResetService;
    private final TokenRevocationService tokenRevocationService;
    private final UserEventPublisher userEventPublisher;
    private final int maxFailedAttempts;
    private final int lockMinutes;

    public AuthServiceImpl(
            UserAuthRepository repository,
            PasswordEncoder passwordEncoder,
            JwtProvider jwtProvider,
            PasswordResetService passwordResetService,
            TokenRevocationService tokenRevocationService,
            UserEventPublisher userEventPublisher,
            @Value("${auth.security.max-failed-attempts:5}") int maxFailedAttempts,
            @Value("${auth.security.lock-minutes:15}") int lockMinutes
    ) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.passwordResetService = passwordResetService;
        this.tokenRevocationService = tokenRevocationService;
        this.userEventPublisher = userEventPublisher;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockMinutes = lockMinutes;
    }

    @Override
    @Transactional
    public LoginResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        if (repository.existsByEmail(email)) {
            throw new UserAlreadyExistsException();
        }
        validatePublicRegisterRole(request.role());
        UserAuth savedUser = repository.save(buildUser(request, email));
        publishCreatedEvent(savedUser.getId(), request.role(), request.name(), request.phone(), request.companyName());
        return buildLoginResponse(savedUser);
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        UserAuth user = findUserByEmail(normalizeEmail(request.email()));
        validateUserAccess(user);
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            throw new InvalidCredentialsException();
        }
        clearFailedAttempts(user);
        return buildLoginResponse(user);
    }

    @Override
    public MeResponse getCurrentUser(String authorizationHeader) {
        JwtPrincipal principal = parsePrincipal(authorizationHeader);
        UserAuth user = repository.findById(principal.userId()).orElseThrow(UserNotFoundException::new);
        return new MeResponse(user.getId(), user.getEmail(), user.getRole().name(), user.isActive());
    }

    @Override
    public void logout(String authorizationHeader) {
        String token = extractBearerToken(authorizationHeader);
        if (jwtProvider.parseToken(token).isEmpty()) {
            throw new InvalidTokenException();
        }
        Instant expiration = jwtProvider.extractExpiration(token).orElseThrow(InvalidTokenException::new);
        tokenRevocationService.revoke(token, expiration);
    }

    @Override
    public void requestPasswordRecovery(ForgotPasswordRequest request) {
        passwordResetService.request(normalizeEmail(request.email()));
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        passwordResetService.reset(request.token().trim(), request.newPassword());
    }

    @Override
    @Transactional
    public void changePassword(String authorizationHeader, ChangePasswordRequest request) {
        JwtPrincipal principal = parsePrincipal(authorizationHeader);
        UserAuth user = repository.findById(principal.userId()).orElseThrow(UserNotFoundException::new);
        validateCurrentPassword(user, request.currentPassword());
        updateUserPassword(user, request.newPassword());
    }

    @Override
    @Transactional
    public void deactivateUser(UUID userId) {
        UserAuth user = repository.findById(userId).orElseThrow(UserNotFoundException::new);
        user.setActive(false);
        user.setUpdatedAt(LocalDateTime.now());
        repository.save(user);
    }

    @Override
    @Transactional
    public void activateUser(UUID userId) {
        UserAuth user = repository.findById(userId).orElseThrow(UserNotFoundException::new);
        user.setActive(true);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedAt(LocalDateTime.now());
        repository.save(user);
    }

    @Override
    public boolean existsSystemAdmin() {
        return repository.existsByRoleAndActiveTrue(UserRole.SYSTEM_ADMIN);
    }

    @Override
    @Transactional
    public AdminCreateUserResponse createUserByAdmin(AdminCreateUserRequest request) {
        String email = normalizeEmail(request.email());
        if (repository.existsByEmail(email)) {
            throw new UserAlreadyExistsException();
        }
        UserAuth user = buildUserForAdmin(request, email);
        UserAuth savedUser = repository.save(user);
        publishCreatedEvent(savedUser.getId(), request.role(), request.name(), request.phone(), request.companyName());
        return mapAdminCreateResponse(savedUser);
    }

    @Override
    public List<AuthUserSummaryResponse> listUsers() {
        return repository.findAllByOrderByCreatedAtDesc().stream().map(this::mapUserSummary).toList();
    }

    private void validatePublicRegisterRole(UserRole role) {
        if (role == UserRole.CLIENT || role == UserRole.ADVERTISER) {
            return;
        }
        throw new InvalidRegistrationException("Solo se permite registro publico para CLIENT y ADVERTISER");
    }

    private void publishCreatedEvent(UUID userId, UserRole role, String name, String phone, String companyName) {
        String normalizedName = normalizeName(name);
        String normalizedPhone = normalizeOptional(phone);
        String normalizedCompanyName = normalizeOptional(companyName);

        try {
            if (role == UserRole.CINEMA_ADMIN) {
                userEventPublisher.publishCinemaAdminCreated(userId, normalizedName, normalizedPhone, normalizedCompanyName);
                return;
            }
            if (role == UserRole.ADVERTISER) {
                userEventPublisher.publishAdvertiserCreated(userId, normalizedName, normalizedPhone);
                return;
            }
            userEventPublisher.publishUserCreated(userId, normalizedName, normalizedPhone);
        } catch (Exception exception) {
            log.error("Error publicando evento de registro para userId={} role={}", userId, role, exception);
        }
    }

    private String normalizeName(String name) {
        String normalized = normalizeOptional(name);
        return normalized == null ? "Usuario" : normalized;
    }

    private String normalizeOptional(String value) {
        if (value == null) {
            return null;
        }
        String trimmedValue = value.trim();
        return trimmedValue.isEmpty() ? null : trimmedValue;
    }

    private UserAuth buildUserForAdmin(AdminCreateUserRequest request, String email) {
        LocalDateTime now = LocalDateTime.now();
        return UserAuth.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(request.role())
                .active(true)
                .requiresPasswordChange(request.forcePasswordChange())
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private AdminCreateUserResponse mapAdminCreateResponse(UserAuth user) {
        return new AdminCreateUserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                user.isActive(),
                user.isRequiresPasswordChange()
        );
    }

    private AuthUserSummaryResponse mapUserSummary(UserAuth user) {
        return new AuthUserSummaryResponse(user.getId(), user.getEmail(), user.getRole().name(), user.isActive());
    }

    private void validateUserAccess(UserAuth user) {
        if (!user.isActive()) {
            throw new InvalidCredentialsException();
        }
        if (isTemporarilyLocked(user)) {
            throw new AccountLockedException();
        }
    }

    private boolean isTemporarilyLocked(UserAuth user) {
        return user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now());
    }

    private void registerFailedAttempt(UserAuth user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= maxFailedAttempts) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockMinutes));
        }
        user.setUpdatedAt(LocalDateTime.now());
        repository.save(user);
    }

    private void clearFailedAttempts(UserAuth user) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedAt(LocalDateTime.now());
        repository.save(user);
    }

    private void validateCurrentPassword(UserAuth user, String currentPassword) {
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
    }

    private void updateUserPassword(UserAuth user, String newPassword) {
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setRequiresPasswordChange(false);
        user.setUpdatedAt(LocalDateTime.now());
        repository.save(user);
    }

    private UserAuth buildUser(RegisterRequest request, String email) {
        LocalDateTime now = LocalDateTime.now();
        return UserAuth.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(request.role())
                .active(true)
                .requiresPasswordChange(false)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private UserAuth findUserByEmail(String email) {
        return repository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    }

    private LoginResponse buildLoginResponse(UserAuth user) {
        String token = jwtProvider.generateToken(user.getId(), user.getEmail(), user.getRole());
        return new LoginResponse(token, user.getId(), user.getEmail(), user.getRole().name());
    }

    private JwtPrincipal parsePrincipal(String authorizationHeader) {
        String token = extractBearerToken(authorizationHeader);
        return jwtProvider.parseToken(token).orElseThrow(InvalidTokenException::new);
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(AuthConstants.BEARER_PREFIX)) {
            throw new InvalidTokenException();
        }
        return authorizationHeader.substring(AuthConstants.BEARER_PREFIX.length()).trim();
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }
}

