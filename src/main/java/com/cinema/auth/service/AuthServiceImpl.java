package com.cinema.auth.service;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.exception.InvalidCredentialsException;
import com.cinema.auth.exception.InvalidTokenException;
import com.cinema.auth.exception.UserAlreadyExistsException;
import com.cinema.auth.exception.UserNotFoundException;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {

    private final UserAuthRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public AuthServiceImpl(UserAuthRepository repository, PasswordEncoder passwordEncoder, JwtProvider jwtProvider) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
    }

    @Override
    @Transactional
    public LoginResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        if (repository.existsByEmail(email)) {
            throw new UserAlreadyExistsException();
        }
        UserAuth savedUser = repository.save(buildUser(request, email));
        return buildLoginResponse(savedUser);
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        UserAuth user = findUserByEmail(normalizeEmail(request.email()));
        if (!isValidCredentials(request.password(), user)) {
            throw new InvalidCredentialsException();
        }
        return buildLoginResponse(user);
    }

    @Override
    public MeResponse getCurrentUser(String authorizationHeader) {
        JwtPrincipal principal = parsePrincipal(authorizationHeader);
        UserAuth user = repository.findById(principal.userId()).orElseThrow(UserNotFoundException::new);
        return new MeResponse(user.getId(), user.getEmail(), user.getRole().name(), user.isActive());
    }

    @Override
    @Transactional
    public void deactivateUser(UUID userId) {
        UserAuth user = repository.findById(userId).orElseThrow(UserNotFoundException::new);
        user.setActive(false);
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
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private UserAuth findUserByEmail(String email) {
        return repository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    }

    private boolean isValidCredentials(String password, UserAuth user) {
        return user.isActive() && passwordEncoder.matches(password, user.getPasswordHash());
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
