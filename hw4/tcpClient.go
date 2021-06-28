package main
 
import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

func clientWriting(con net.Conn, wg *sync.WaitGroup){
	defer wg.Done()
	clientReader := bufio.NewReader(os.Stdin)
	for {
		// Waiting for the client request
		clientRequest, err := clientReader.ReadString('\n')
 
		switch err {
		case nil:
			clientRequest := strings.TrimSpace(clientRequest)
			if _, err = con.Write([]byte(clientRequest + "\n")); err != nil {
				log.Printf("failed to send the client request: %v\n", err)
			}
		case io.EOF:
			log.Println("client closed the connection")
			return
		default:
			log.Printf("client error: %v\n", err)
			return
		}
	}
}

func clientReading(con net.Conn, wg *sync.WaitGroup){
	defer wg.Done()
	serverReader := bufio.NewReader(con)
	for {
		serverResponse, err := serverReader.ReadString('\n')
 
		switch err {
		case nil:
			log.Println(strings.TrimSpace(serverResponse))
		case io.EOF:
			log.Println("server closed the connection")
			return
		default:
			log.Printf("server error: %v\n", err)
			return
		}
	}
}
 
func main() {
	con, err := net.Dial("tcp", "192.168.141.128:9999")
	if err != nil {
		log.Fatalln(err)
	}
	defer con.Close()
 
	
	// serverReader := bufio.NewReader(con)
	var wg sync.WaitGroup

	wg.Add(1)
	go clientWriting(con, &wg)
	go clientReading(con, &wg)
	wg.Wait()
	// for {
	// 	// Waiting for the client request
	// 	clientRequest, err := clientReader.ReadString('\n')
 
	// 	switch err {
	// 	case nil:
	// 		clientRequest := strings.TrimSpace(clientRequest)
	// 		if _, err = con.Write([]byte(clientRequest + "\n")); err != nil {
	// 			log.Printf("failed to send the client request: %v\n", err)
	// 		}
	// 	case io.EOF:
	// 		log.Println("client closed the connection")
	// 		return
	// 	default:
	// 		log.Printf("client error: %v\n", err)
	// 		return
	// 	}
 
		// Waiting for the server response
		// serverResponse, err := serverReader.ReadString('\n')
 
		// switch err {
		// case nil:
		// 	log.Println(strings.TrimSpace(serverResponse))
		// case io.EOF:
		// 	log.Println("server closed the connection")
		// 	return
		// default:
		// 	log.Printf("server error: %v\n", err)
		// 	return
		// }
	// }
}