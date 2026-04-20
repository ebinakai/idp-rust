-- Add migration script here
CREATE TABLE user_consents (
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
    
    CONSTRAINT fk_user_consents_client_id 
        FOREIGN KEY (client_id) 
        REFERENCES oauth_clients(id)
        ON DELETE CASCADE
);