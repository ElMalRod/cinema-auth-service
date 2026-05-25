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
    public static final String JWT_KEY_ID = "cinema-key";
    public static final long JWT_DEFAULT_EXPIRATION_SECONDS = 3600L;

    public static final String RSA_ALGORITHM = "RSA";
    public static final int RSA_KEY_SIZE = 2048;
    public static final String PUBLIC_KEY_ENDPOINT = "/auth/public-key";
    public static final String AUTH_BASE_PATH = "/auth";
    public static final String AUTH_LOGIN_PATH = "/login";
    public static final String AUTH_REGISTER_PATH = "/register";
    public static final String AUTH_ME_PATH = "/me";
    public static final String AUTH_LOGOUT_PATH = "/logout";
    public static final String AUTH_FORGOT_PASSWORD_PATH = "/forgot-password";
    public static final String AUTH_RESET_PASSWORD_PATH = "/reset-password";
    public static final String AUTH_CHANGE_PASSWORD_PATH = "/change-password";
    public static final String AUTH_DEACTIVATE_PATH = "/deactivate/{id}";
    public static final String AUTH_ACTIVATE_PATH = "/activate/{id}";
    public static final String AUTH_EXISTS_ADMIN_PATH = "/exists-admin";
    public static final String AUTH_ADMIN_CREATE_USER_PATH = "/admin/create-user";
    public static final String AUTH_ADMIN_LIST_PATH = "/admin/list";
    public static final String AUTH_ADMIN_DEACTIVATE_PATH = "/admin/deactivate/{id}";
    public static final String AUTH_ADMIN_ACTIVATE_PATH = "/admin/activate/{id}";

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String INTERNAL_SERVICE_HEADER = "X-Internal-Service";
    public static final String INTERNAL_SERVICE_HEADER_VALUE = "true";

    public static final String PEM_PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    public static final String PEM_PUBLIC_KEY_END = "-----END PUBLIC KEY-----";
    public static final String PEM_LINE_SEPARATOR = "\n";

    public static final String MESSAGE_INVALID_CREDENTIALS = "Credenciales invalidas";
    public static final String MESSAGE_USER_EXISTS = "El usuario ya existe";
    public static final String MESSAGE_USER_NOT_FOUND = "Usuario no encontrado";
    public static final String MESSAGE_INVALID_TOKEN = "Token invalido";
    public static final String MESSAGE_ACCOUNT_LOCKED = "Cuenta bloqueada temporalmente por intentos fallidos";
    public static final String MESSAGE_RESET_TOKEN_INVALID = "Token de recuperacion invalido o expirado";
    public static final String MESSAGE_RESET_MAIL_FAILURE = "No se pudo enviar el correo de recuperacion";

    public static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;
    public static final int DEFAULT_LOCK_MINUTES = 15;
    public static final int DEFAULT_RESET_TOKEN_MINUTES = 30;

    public static final String BREVO_BASE_URL = "https://api.brevo.com/v3";
    public static final String BREVO_API_KEY_HEADER = "api-key";
    public static final String BREVO_EMAIL_PATH = "/smtp/email";
    public static final String DEFAULT_FRONTEND_BASE_URL = "http://cinema-frontend-s3.s3-website.us-east-2.amazonaws.com";
    public static final String DEFAULT_SENDER_NAME = "Cinema";

    private AuthConstants() {
    }
}
