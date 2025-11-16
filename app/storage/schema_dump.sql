-- MySQL Schema Dump for SecureChat Assignment #2
-- Database: securechat
-- Table: users

-- Create database (if it doesn't exist)
CREATE DATABASE IF NOT EXISTS securechat;
USE securechat;

-- Drop table if exists (for clean reinstall)
DROP TABLE IF EXISTS users;

-- Create users table
-- Stores username, salt (16-byte random), and SHA-256 password hash
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample records (example data)
-- Note: These are example records. In production, salts should be cryptographically random.
-- The pwd_hash is SHA-256(salt || password) as hex string (64 characters)

-- Example user: alice
-- Password: "mypassword"
-- Salt (hex): 0123456789abcdef0123456789abcdef (16 bytes)
-- Hash: SHA-256(salt || "mypassword") = [computed value]
INSERT INTO users (username, salt, pwd_hash) VALUES 
('alice', UNHEX('0123456789abcdef0123456789abcdef'), 'example_hash_here_64_chars_long_sha256_hex_digest_placeholder');

-- Example user: bob  
-- Password: "secret123"
-- Salt (hex): fedcba9876543210fedcba9876543210 (16 bytes)
INSERT INTO users (username, salt, pwd_hash) VALUES 
('bob', UNHEX('fedcba9876543210fedcba9876543210'), 'another_example_hash_64_chars_long_sha256_hex_digest_placeholder');

-- Note: To generate actual hashes, run the Python code:
-- python app/storage/db.py
-- This will create real users with proper salts and hashes.

