CREATE TABLE webauthn_credentials (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    credential_id VARCHAR(512) NOT NULL UNIQUE,
    label VARCHAR(255) NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_webauthn_user_id (user_id),
    CONSTRAINT fk_webauthn_credentials_user_id
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);
