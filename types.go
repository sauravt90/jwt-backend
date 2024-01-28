package main

type IdPass struct {
	Id       string `json:"id"`
	Password string `json:"password"`
}

type Token struct {
	Token string `json:"token"`
}
