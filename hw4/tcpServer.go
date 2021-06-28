package main

import (
	"bufio"
	"io"
	"log"
	"net"
	// "strings"
)
 
func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:9999")
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()
 
	for {
		con, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
 
		// If you want, you can increment a counter here and inject to handleClientRequest below as client identifier
		go handleClientRequest(con)
	}
}
 
func handleClientRequest(con net.Conn) {
	defer con.Close()
 
	clientReader := bufio.NewReader(con)
	buf := make([]byte, 16)
 
	for {
		// Waiting for the client request
		clientRequest, err := clientReader.Read(buf)
 
		switch err {
		case nil:
			log.Println(clientRequest)
		case io.EOF:
			log.Println("client closed the connection by terminating the process")
			return
		default:
			log.Printf("error: %v\n", err)
			return
		}
 
		// Responding to the client request
		if _, err = con.Write([]byte("GOT IT!\n")); err != nil {
			log.Printf("failed to respond to client: %v\n", err)
		}
	}
}