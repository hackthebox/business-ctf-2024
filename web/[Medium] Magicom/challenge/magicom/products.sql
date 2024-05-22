CREATE DATABASE IF NOT EXISTS magicom;

-- Create products table
CREATE TABLE IF NOT EXISTS magicom.products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    description TEXT,
    image_url VARCHAR(255)
);

-- Create users table
CREATE TABLE IF NOT EXISTS magicom.users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(255)
);

-- Insert dummy data into products table
INSERT INTO magicom.products (title, description, image_url) VALUES 
('Pew Pew', "Introducing the 'Pew Pew' - the ultimate energy weapon for discerning wasteland adventurers in Fallout: New Vegas! Are you tired of conventional firearms that just don't pack enough punch? Look no further, because the 'Pew Pew' is here to revolutionize your combat experience.", '/assets/image/Pew_Pew.jpeg'),
('Tesla Canon', 'Step right up, wasteland wanderers, and behold the marvel that is the Tesla Cannon! Are you tired of relying on puny firearms to face the dangers of the wasteland? Well, look no further, because the Tesla Cannon is here to electrify your combat experience!', '/assets/image/Tesla_cannon.jpeg'),
('Protonic inversal throwing axe', 'Greetings, wasteland warriors! Feast your eyes on the marvel that is the Protonic Inversal Throwing Axe! Are you tired of relying on conventional weapons to face the perils of the wasteland? Look no further, because the Protonic Inversal Throwing Axe is here to revolutionize your combat style!', '/assets/image/Protonic_inversal_throwing_axe.jpeg'), 
('CZ57 Avenger', 'Step right up, wasteland warriors, and behold the CZ57 Avenger - the ultimate solution to all your firepower needs! Are you tired of being outgunned by raiders and mutants alike? Well, fret no more, because the CZ57 Avenger is here to turn the tide of battle in your favor!', '/assets/image/CZ57Avenger.jpeg'), 
('That Gun', "Step right up, fellow wasteland wanderers, and feast your eyes on a true classic: That Gun! Are you tired of settling for mediocre firearms that just don't pack the punch you need to survive out here? Well, look no further, because That Gun is the answer to all your problems!", '/assets/image/FNVThatGun.jpeg'), 
('Alien blaster', "Greetings, fellow wanderers of the wasteland! Have you ever gazed up at the night sky and wondered if we're truly alone in the universe? Well, wonder no more, because I bring to you a weapon that defies earthly explanation: the Alien Blaster!", '/assets/image/F3Firelance.jpeg');

-- Create user and grant privileges]:::
CREATE USER IF NOT EXISTS 'beluga'@'localhost' IDENTIFIED BY 'beluga';
GRANT SELECT, UPDATE, INSERT ON *.* TO 'beluga'@'localhost';
ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';
FLUSH PRIVILEGES;
