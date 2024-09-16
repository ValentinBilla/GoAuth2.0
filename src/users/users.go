package users

import "github.com/alexedwards/argon2id"

var users = make(map[string]User)

type User struct {
	Username string
	Hash     string
}

// InitUsers initializes a set of default users with predefined usernames and passwords in the system.
// TODO: Delete InitUsers and support database for such things
func InitUsers() {
	AddUser("vbilla", "password1234")
}

func AddUser(username string, password string) User {
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	user := User{
		Username: username,
		Hash:     hash,
	}

	users[username] = user
	return user
}

func GetUser(username string) User {
	return users[username]
}
