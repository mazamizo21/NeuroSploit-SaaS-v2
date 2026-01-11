-- PostgreSQL Initialization
CREATE DATABASE secrets;
\c secrets

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    service VARCHAR(100),
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO api_keys (service, api_key) VALUES
('stripe', 'sk_test_FAKE_KEY_FOR_TESTING_ONLY'),
('sendgrid', 'SG_FAKE_KEY_FOR_TESTING_ONLY'),
('twilio', 'SK_FAKE_KEY_FOR_TESTING_ONLY'),
('aws', 'FAKE_AWS_KEY_FOR_TESTING');

CREATE TABLE users_backup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100)
);

INSERT INTO users_backup VALUES
(1, 'admin', 'admin123', 'admin@company.local'),
(2, 'root', 'toor', 'root@company.local');
