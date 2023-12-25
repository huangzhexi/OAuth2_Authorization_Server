package models

// User model
type User struct {
	Username     string
	HashPassword string
	Salt         string
	Comments     string //currently User's real name.
}

func newDefaultUser(username string) *User {
	return &User{Username: username}
}

func newUser(username string, hashPassword string, salt string, comments string) *User {
	return &User{Username: username, HashPassword: hashPassword, Salt: salt, Comments: comments}
}
