
DROP DATABASE IF EXISTS springsecurity;
create DATABASE springsecurity;
use springsecurity;
create table users (
  id INTEGER PRIMARY KEY,
  username varchar(50) not null,
  password text not null
);
INSERT INTO users (id, username, password) VALUES (1, 'user1', 'password1');
INSERT INTO users (id, username, password) VALUES (2, 'user2', 'password2');