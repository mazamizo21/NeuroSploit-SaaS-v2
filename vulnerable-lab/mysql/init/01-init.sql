-- MySQL Initialization Script - Vulnerable Database
-- Contains sensitive data for penetration testing

-- Create additional databases
CREATE DATABASE IF NOT EXISTS enterprise;
CREATE DATABASE IF NOT EXISTS hr_records;
CREATE DATABASE IF NOT EXISTS financial;

USE enterprise;

-- Users table with weak password storage
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Plain text passwords (vulnerable)
    email VARCHAR(100),
    role ENUM('admin', 'user', 'guest') DEFAULT 'user',
    api_key VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users with weak passwords
INSERT INTO users (username, password, email, role, api_key) VALUES
('admin', 'admin123', 'admin@company.local', 'admin', 'sk-admin-secret-key-12345'),
('john.smith', 'password123', 'john.smith@company.local', 'user', 'sk-user-john-67890'),
('jane.doe', 'jane2024', 'jane.doe@company.local', 'user', 'sk-user-jane-11111'),
('guest', 'guest', 'guest@company.local', 'guest', NULL),
('backup_admin', 'backup2024!', 'backup@company.local', 'admin', 'sk-backup-admin-99999'),
('service_account', 'svc_p@ssw0rd', 'service@company.local', 'admin', 'sk-service-00000');

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(50)
);

INSERT INTO products (name, description, price, category) VALUES
('Enterprise License', 'Full enterprise software license', 9999.99, 'software'),
('Support Package', 'Premium support package', 4999.99, 'services'),
('Training Course', 'Security training course', 1999.99, 'training');

-- Confidential documents table
CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200),
    content TEXT,
    classification ENUM('public', 'internal', 'confidential', 'secret'),
    owner_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO documents (title, content, classification, owner_id) VALUES
('Public Policy', 'This is our public policy document.', 'public', 1),
('Internal Memo', 'Q4 revenue target: $50M', 'internal', 1),
('Confidential: Merger Plans', 'We are acquiring CompetitorCorp for $500M', 'confidential', 1),
('SECRET: Server Credentials', 'Root password for all servers: SuperSecret123!', 'secret', 1),
('SECRET: API Keys', 'AWS Key: AKIAIOSFODNN7EXAMPLE, Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'secret', 1);

-- Credit card data (for PCI testing)
CREATE TABLE credit_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(20),  -- Unencrypted (vulnerable)
    cvv VARCHAR(4),           -- Should never be stored
    expiry VARCHAR(7),
    cardholder_name VARCHAR(100)
);

INSERT INTO credit_cards (user_id, card_number, cvv, expiry, cardholder_name) VALUES
(1, '4111111111111111', '123', '12/2025', 'Admin User'),
(2, '5500000000000004', '456', '06/2026', 'John Smith'),
(3, '340000000000009', '7890', '03/2025', 'Jane Doe');

-- HR Records database
USE hr_records;

CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(20),
    full_name VARCHAR(100),
    ssn VARCHAR(11),  -- Social Security Number (vulnerable)
    salary DECIMAL(10,2),
    department VARCHAR(50),
    manager_id INT
);

INSERT INTO employees (employee_id, full_name, ssn, salary, department, manager_id) VALUES
('EMP001', 'John Smith', '123-45-6789', 85000.00, 'Engineering', NULL),
('EMP002', 'Jane Doe', '987-65-4321', 92000.00, 'Engineering', 1),
('EMP003', 'Bob Wilson', '456-78-9012', 150000.00, 'Executive', NULL),
('EMP004', 'Alice Brown', '789-01-2345', 78000.00, 'HR', 3);

-- Financial database
USE financial;

CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_number VARCHAR(20),
    transaction_type ENUM('credit', 'debit'),
    amount DECIMAL(15,2),
    description VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO transactions (account_number, transaction_type, amount, description) VALUES
('ACC-001-ADMIN', 'credit', 1000000.00, 'Initial funding'),
('ACC-001-ADMIN', 'debit', 50000.00, 'Equipment purchase'),
('ACC-002-OPS', 'credit', 500000.00, 'Q4 budget allocation'),
('ACC-003-SECRET', 'credit', 10000000.00, 'Offshore transfer');

-- Create additional user with full privileges (vulnerable)
CREATE USER IF NOT EXISTS 'backup'@'%' IDENTIFIED BY 'backup123';
GRANT ALL PRIVILEGES ON *.* TO 'backup'@'%';
FLUSH PRIVILEGES;
