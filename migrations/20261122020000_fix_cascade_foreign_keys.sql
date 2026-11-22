ALTER TABLE user_consents
    DROP FOREIGN KEY user_consents_ibfk_1,
    DROP FOREIGN KEY user_consents_ibfk_2,
    ADD CONSTRAINT fk_user_consents_user_id
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE;

ALTER TABLE refresh_tokens
    MODIFY COLUMN client_id VARCHAR(255) NOT NULL,
    ADD CONSTRAINT fk_refresh_tokens_client_id
        FOREIGN KEY (client_id)
        REFERENCES oauth_clients(id)
        ON DELETE CASCADE;
