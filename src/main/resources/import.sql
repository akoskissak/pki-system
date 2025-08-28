INSERT INTO role (id, name) VALUES (1, 'ADMIN');
INSERT INTO role (id, name) VALUES (2, 'CA_USER');
INSERT INTO role (id, name) VALUES (3, 'END_USER');

INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('admin@pki-system.com', '$2a$10$ChxeCMeH3bWi7j8J/YFONuF0ZCmFZv6BLi/wp49l1VZCTTLYbxAu2', 'System', 'Administrator', 'MainOrg', true, 1);
INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('kiss.akos02@gmail.com', '$2a$12$1dAGhd4gVXjcLACrRHPJzOSwqVAcpIhgwDPxVUKU3eSTx7HcGXz9y', 'Akos', 'Kiss', 'AkorORG', true, 3);
INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('causer@pki-system.com', '$2a$10$ChxeCMeH3bWi7j8J/YFONuF0ZCmFZv6BLi/wp49l1VZCTTLYbxAu2', 'CA', 'User', 'CA-Org', true, 2);
INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('eeuser@pki-system.com', '$2a$10$BDOnxr1mEDc9VMDAqq9tSOcWzeCFbFmW5eZC8wEyPoJ.SuU83.Mlq', 'Jana', 'Jankovic', 'FTN', true, 3);

UPDATE users SET symmetric_key = 'S1XnKzL8oVp9qRtYF5j2zM7gVbH4cE3aJdYwP0uIeUo=' WHERE email = 'causer@pki-system.com';
UPDATE users SET symmetric_key = 'KcfRHpE5wrRgWk7gRvLSK9ZKk1FXnJkigHD32ZUqT2o=' WHERE email = 'admin@pki-system.com';