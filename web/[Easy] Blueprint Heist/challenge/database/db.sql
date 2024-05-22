create database construction;

CREATE TABLE construction.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name TEXT,
    department TEXT,
    isPresent BOOLEAN
);

INSERT INTO construction.users (name, department, isPresent)
VALUES
    ('John Doe', 'construction', 1),
    ('Alice Smith', 'safety', 0),
    ('Bob Johnson', 'equipments', 0),
    ('Jane Brown', 'construction', 1),
    ('Michael Lee', 'safety', 0),
    ('Sarah Clark', 'equipments', 1),
    ('David Martinez', 'construction', 1),
    ('Emily Rodriguez', 'safety', 0),
    ('Christopher Anderson', 'equipments', 1),
    ('Jessica Taylor', 'construction', 0),
    ('Daniel Thomas', 'safety', 1),
    ('Jennifer Hernandez', 'equipments', 0),
    ('Matthew Walker', 'construction', 1),
    ('Amanda Young', 'safety', 0),
    ('James King', 'equipments', 1),
    ('Melissa White', 'construction', 1),
    ('Kevin Scott', 'safety', 1),
    ('Laura Hill', 'equipments', 1),
    ('Joshua Green', 'construction', 1),
    ('Rebecca Baker', 'safety', 0),
    ('Ryan Evans', 'equipments', 0),
    ('Stephanie Adams', 'construction', 1),
    ('Eric Wright', 'safety', 1),
    ('Kimberly Mitchell', 'equipments', 1),
    ('Justin Carter', 'construction', 0),
    ('Nicole Hall', 'safety', 1),
    ('Brandon Rivera', 'equipments', 1),
    ('Ashley Ward', 'construction', 1),
    ('Brett Phillips', 'safety', 0),
    ('Samantha Flores', 'equipments', 1);

CREATE USER 'root'@'%' IDENTIFIED BY 'Secr3tP4ssw0rdNoGu35s!'; 
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;