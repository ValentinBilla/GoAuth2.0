package clients

import "GoAuth2.0/utils"

var clients = make(map[string]Client)

type Client struct {
	Name        string
	Id          string
	RedirectUri string
}

// InitUsers initializes a set of default users with predefined usernames and passwords in the system.
// TODO: Delete InitUsers and support database for such things
func InitClients() {
	createClient("Twittin", "JL1BL6YInEZpdLkMHcKIp7kCJ1S3XlRuxpoNpKvFpUU", "https://twittin.com/callback")
	createClient("Facebruck", "o4lil9pce6CI5O6Ffzg4lrp4vGxkzI-toYt5zrDPPc4", "https://oauth.facebruck.com/go-auth")
}

func createClient(name string, id string, redirectUri string) Client {
	client := Client{
		Name:        name,
		Id:          id,
		RedirectUri: redirectUri,
	}
	clients[id] = client
	return client
}

func AddClient(name string, redirectUri string) Client {
	id := utils.GenerateRandomCode()

	client := Client{
		Name:        name,
		Id:          id,
		RedirectUri: redirectUri,
	}
	clients[id] = client
	return client
}

func GetClient(id string) Client {
	return clients[id]
}
