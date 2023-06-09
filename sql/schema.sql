PRAGMA foreign_keys = ON;

CREATE TABLE users(
  username VARCHAR(20) NOT NULL,
  fullname VARCHAR(40) NOT NULL,
  email VARCHAR(40),
  filename VARCHAR(64),
  password VARCHAR(256),
  created DATETIME,
  PRIMARY KEY(username)
);

CREATE TABLE posts(
  postid INTEGER PRIMARY KEY AUTOINCREMENT,
  filename VARCHAR(64),
  owner VARCHAR(20),
  created DATETIME,
  FOREIGN KEY(owner) REFERENCES users ON DELETE CASCADE
);

CREATE TABLE following(
  username1 VARCHAR(20),
  username2 VARCHAR(20),
  created DATETIME,
  PRIMARY KEY(username1, username2)
  FOREIGN KEY(username1) REFERENCES users ON DELETE CASCADE,
  FOREIGN KEY(username2) REFERENCES users ON DELETE CASCADE
);

CREATE TABLE comments(
  commentid INTEGER PRIMARY KEY AUTOINCREMENT,
  owner VARCHAR(20),
  postid INTEGER,
  text VARCHAR(1024),
  created DATETIME,
  FOREIGN KEY(owner) REFERENCES users ON DELETE CASCADE,
  FOREIGN KEY(postid) REFERENCES posts ON DELETE CASCADE
);

CREATE TABLE likes(
  likeid INTEGER PRIMARY KEY AUTOINCREMENT,
  owner VARCHAR(20),
  postid INTEGER,
  created DATETIME,
  FOREIGN KEY(owner) REFERENCES users ON DELETE CASCADE,
  FOREIGN KEY(postid) REFERENCES posts ON DELETE CASCADE
);