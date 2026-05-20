package com.cinema.auth.constants;

public final class AuthConstants {

    public static final String OPEN_API_TITLE = "Cinema Auth Service API";
    public static final String OPEN_API_VERSION = "1.0";
    public static final String OPEN_API_DESCRIPTION = "Microservicio de autenticacion del sistema de cines";
    public static final String BEARER_SCHEME_NAME = "bearerAuth";
    public static final String BEARER_SCHEME = "bearer";
    public static final String BEARER_FORMAT = "JWT";

    public static final String JWT_ISSUER = "cinema-auth-service";
    public static final String JWT_CLAIM_EMAIL = "email";
    public static final String JWT_CLAIM_ROLES = "roles";
    public static final long JWT_DEFAULT_EXPIRATION_SECONDS = 3600L;

    public static final String RSA_ALGORITHM = "RSA";
    public static final int RSA_KEY_SIZE = 2048;
    public static final String PUBLIC_KEY_ENDPOINT = "/auth/public-key";
    public static final String AUTH_BASE_PATH = "/auth";
    public static final String AUTH_LOGIN_PATH = "/login";
    public static final String AUTH_REGISTER_PATH = "/register";
    public static final String AUTH_ME_PATH = "/me";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    public static final String PEM_PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    public static final String PEM_PUBLIC_KEY_END = "-----END PUBLIC KEY-----";
    public static final String PEM_LINE_SEPARATOR = "\n";

    public static final String MESSAGE_INVALID_CREDENTIALS = "Credenciales invalidas";
    public static final String MESSAGE_USER_EXISTS = "El usuario ya existe";
    public static final String MESSAGE_USER_NOT_FOUND = "Usuario no encontrado";
    public static final String MESSAGE_INVALID_TOKEN = "Token invalido";

    private AuthConstants() {
    }
}
