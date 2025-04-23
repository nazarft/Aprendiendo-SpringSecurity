
DROP DATABASE IF EXISTS springsecurity;
create DATABASE springsecurity;
use springsecurity;
create table users (
  id INTEGER PRIMARY KEY AUTO_INCREMENT,
  firstname varchar(50) not null,
  lastname varchar(50) not null,
  username varchar(50) not null,
  email text NOT NULL,
  password text not null
);
