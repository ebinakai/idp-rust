-- Add migration script here
CREATE TABLE refresh_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(355) NOT NULL,
    expires_at DATETIME NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user_client (user_id, client_id),

    CONSTRAINT fk_refresh_tokens_user_id
            FOREIGN KEY (user_id) 
            REFERENCES users(id)
            ON DELETE CASCADE
);
