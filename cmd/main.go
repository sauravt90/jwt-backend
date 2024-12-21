package main

import (
	s "apis/server"
)

func main() {

	server := s.NewServer(":8081")
	server.Run()
}
