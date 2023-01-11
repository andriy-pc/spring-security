CREATE TABLE users
(
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(50) NOT NULL,
  second_name VARCHAR(50) NOT NULL,
  login VARCHAR(25) NOT NULL,
  password VARCHAR(50) NOT NULL
);

CREATE TABLE roles
(
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL
);

CREATE TABLE user_roles
(
  user_id INT REFERENCES users (id),
  role_id INT REFERENCES roles (id),
  PRIMARY KEY (user_id, role_id)
);

INSERT INTO users (first_name, second_name, login, password)
VALUES
('John', 'Doe', 'johndoe', 'root'),
('Big', 'Smoke', 'train', 'root'),
('C', 'doj', 'doj', 'root');

INSERT INTO roles (name)
VALUES
('ROLE_ADMIN'),
('ROLE_USER');

INSERT INTO user_roles (user_id, role_id)
VALUES
(1, 2),
(2, 2),
(3, 1);