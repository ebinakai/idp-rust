-- Add migration script here
CREATE TABLE oauth_clients (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    secret VARCHAR(255), 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE oauth_client_redirect_uris (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    uri VARCHAR(512) NOT NULL,
    UNIQUE(client_id, uri),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
);

-- 初期データの投入
INSERT INTO oauth_clients (id, name, secret) VALUES 
('test_client_app', 'Test Client App', "$argon2id$v=19$m=19456,t=2,p=1$8ccd+Ns2njGepGvb7bvp+Q$5rQCOGxTEFDyHklsGHtwqzckKyKQfSt97H3xe9icx4I");

INSERT INTO oauth_client_redirect_uris (client_id, uri) VALUES 
('test_client_app', 'http://localhost:4000/callback'),
('test_client_app', 'http://localhost:4000');
