CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE user_role AS ENUM (
    'SYSTEM_ADMIN',
    'CINEMA_ADMIN',
    'CLIENT',
    'ADVERTISER'
);

CREATE TABLE users_auth (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          user_role    NOT NULL,
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_auth_email  ON users_auth(email);
CREATE INDEX idx_users_auth_role   ON users_auth(role);
CREATE INDEX idx_users_auth_active ON users_auth(active);
