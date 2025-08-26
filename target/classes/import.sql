INSERT INTO role (id, name) VALUES (1, 'ADMIN');
INSERT INTO role (id, name) VALUES (2, 'CA_USER');
INSERT INTO role (id, name) VALUES (3, 'END_USER');

INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('admin@pki-system.com', '$2a$10$ChxeCMeH3bWi7j8J/YFONuF0ZCmFZv6BLi/wp49l1VZCTTLYbxAu2', 'System', 'Administrator', 'MainOrg', true, 1);
INSERT INTO users (email, password, first_name, last_name, organization, enabled, role_id) VALUES ('kiss.akos02@gmail.com', '$2a$12$1dAGhd4gVXjcLACrRHPJzOSwqVAcpIhgwDPxVUKU3eSTx7HcGXz9y', 'Akos', 'Kiss', 'AkorORG', true, 3);