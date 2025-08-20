INSERT INTO role (id, name) VALUES (1, 'ADMIN');
INSERT INTO role (id, name) VALUES (2, 'CA_USER');
INSERT INTO role (id, name) VALUES (3, 'END_USER');

INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('admin@pki-system.com', '$2a$10$7QGfS3ZpZ7fV5SAgMvlKduQk8q8qZd/2nxC2ZlH1a9U/7RZgX9WCu', 'System', 'Administrator', 'MainOrg', true, 1);