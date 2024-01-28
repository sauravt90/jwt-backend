package main

func main() {

	server := NewServer(":8081")
	server.Run()
}
