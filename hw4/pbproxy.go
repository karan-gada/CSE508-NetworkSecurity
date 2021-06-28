package main
 
import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"github.com/pborman/getopt"
	"golang.org/x/crypto/pbkdf2"
	"crypto/aes"
    "crypto/sha1"
    "crypto/cipher"
    "crypto/rand"
	"time"
)

var(
	listen_port_ptr *string
	key_file_ptr *string
	dst_ip string
	dst_port string
	passPhrase []byte
)

const BUFF_SIZE int = 1024
const DELAY_FOR_ENC_PKT time.Duration = time.Millisecond * 10
const SALT_LEN int = 16

func serverSideSetup(){
	//Creating a listener to listen on the given port
	listener, err := net.Listen("tcp", ":" + (*listen_port_ptr))
	if err != nil {
		log.Fatalf("Server : Error in Listening on the port -> %v\n", err)
	}
	defer listener.Close()

 
	for {
		// This is the loop for listening to clients and accepting them
		client_socket, err := listener.Accept()
		if err != nil {
			log.Fatalf("Server : Error in Accepting for Connections -> %v\n", err)
			continue
		}
		defer client_socket.Close()

		relay_con, err := net.Dial("tcp", dst_ip + ":" + dst_port)
		if err != nil {
			log.Printf("Server: Error in connection to Private Service -> %v\n", err)
			client_socket.Close()
			continue
		}
		defer relay_con.Close()
 
		// Spawing two new thread for every client to -
		// 1. reading from client -> decryption -> writing to private port
		// 2. reading from private port -> encryption -> writing to the client
		go serverReadClient(client_socket, relay_con)
		go serverWriteClient(relay_con, client_socket)
	}
}

func serverReadClient(src_con net.Conn, dst_con net.Conn) {
	defer src_con.Close()
	defer dst_con.Close()

	clientReader := bufio.NewReader(src_con)
	serviceWriter := bufio.NewWriter(dst_con)
	buf_ := make([]byte, 2 * BUFF_SIZE)
 
	for {
		// This is the loop to read the encrypted data sent by the client
		length_, err := clientReader.Read(buf_)
 
		switch err {
		case nil:
			decrypted_message_ := aesgcmDecryption(buf_[:length_])

			//Write the decrypted data to the private port
			if _, err = serviceWriter.Write([]byte(decrypted_message_)); err != nil{
				log.Printf("Server : Writing to Service Failed -> %v\n", err)
			} else{
				serviceWriter.Flush()
			}

		case io.EOF:
			// log.Printf("Server : Client closed connection by termination %v %v -> %v %v\n", src_con.LocalAddr(), src_con.RemoteAddr(), dst_con.LocalAddr(), dst_con.RemoteAddr())
			return
		default:
			// log.Printf("Server : Error: %v\n", err)
			return
		}
	}
}

func serverWriteClient(src_con net.Conn, dst_con net.Conn) {
	defer src_con.Close()
	defer dst_con.Close()

	serviceReader := bufio.NewReader(src_con)
	clientWriter := bufio.NewWriter(dst_con)
	buf_ := make([]byte, BUFF_SIZE)
 
	for {
		// This is the loop to read the plaintext data from the private port
		length_, err := serviceReader.Read(buf_)
 
		switch err {
		case nil:
			encrypted_message_ := aesgcmEncryption(buf_[:length_])

			//Write the encrypted data to the client
			if _, err = clientWriter.Write([]byte(encrypted_message_)); err != nil{
				log.Printf("Server : Writing to Client Failed -> %v\n", err)
			} else{
				clientWriter.Flush()
				time.Sleep(DELAY_FOR_ENC_PKT)
			}

		
		case io.EOF:
			// log.Printf("Server : Client closed connection by termination %v %v -> %v %v\n", src_con.LocalAddr(), src_con.RemoteAddr(), dst_con.LocalAddr(), dst_con.RemoteAddr())
			return
		default:
			// log.Printf("Server : Error: %v\n", err)
			return
		}
	}
}

func clientSideSetup(){
	server_socket, err := net.Dial("tcp", dst_ip + ":" + dst_port)
	if err != nil {
		log.Fatalf("Client : Error in Connecting to the server -> %v\n", err)
	}
	defer server_socket.Close()

	//Using waitGroup for client application to wait for the child threads to return before returning from the main thread
	var wg sync.WaitGroup

	// Spawing two new thread for the client application to -
	// 1. reading from standard input -> ecryption -> writing to server
	// 2. reading from server -> dencryption -> writing to the standard output
	wg.Add(1)
	go handleClientRequest(server_socket, &wg)
	go handleClientResponse(server_socket, &wg)
	wg.Wait()
}

func handleClientRequest(dst_con net.Conn, wg *sync.WaitGroup){
	defer wg.Done()
	defer dst_con.Close()
	
	stdinReader := bufio.NewReader(os.Stdin)
	serverWriter := bufio.NewWriter(dst_con)
	buf_ := make([]byte, BUFF_SIZE)

	for {
		// This is the loop for reading the plaintext data from the standard input of the client
		length_, err := stdinReader.Read(buf_)
 
		switch err {
		case nil:
			encrypted_message_ := aesgcmEncryption(buf_[:length_])
			//Write the encrypted data to the server
			_, err := serverWriter.Write([]byte(encrypted_message_))
			if err != nil {
				log.Printf("Client : Writing to Server Failed -> %v\n", err)
			} else{
				serverWriter.Flush()
				time.Sleep(DELAY_FOR_ENC_PKT)
			}
		case io.EOF:
			// log.Printf("Client : client closed the connection %v %v\n", dst_con.LocalAddr(), dst_con.RemoteAddr())
			return
		default:
			// log.Printf("Client : Error: %v\n %v %v\n", err, dst_con.LocalAddr(), dst_con.RemoteAddr())
			return
		}
	}
}

func handleClientResponse(src_con net.Conn, wg *sync.WaitGroup){
	defer wg.Done()
	defer src_con.Close()

	serverReader := bufio.NewReader(src_con)
	stdOutWriter := bufio.NewWriter(os.Stdout)
	buf_ := make([]byte, 2 * BUFF_SIZE)
	for {
		// This is the loop for reading the encrypted data from the server
		length_, err := serverReader.Read(buf_)
 
		switch err {
		case nil:
			decrypted_message_ := aesgcmDecryption(buf_[:length_])

			//Write the decrypted data to the standard output of the client
			if _, err = stdOutWriter.Write([]byte(decrypted_message_)); err != nil {
				log.Printf("Client : Writing to Standard Output Failed -> %v\n", err)
			} else{
				stdOutWriter.Flush()
			}
		case io.EOF:
			// log.Printf("Client : client closed the connection %v %v\n", src_con.LocalAddr(), src_con.RemoteAddr())
			return
		default:
			// log.Printf("Client : Error: %v\n %v %v\n", err, src_con.LocalAddr(), src_con.RemoteAddr())
			return
		}
	}
}

func aesgcmEncryption(plain_text []byte) []byte {

	salt_ := make([]byte, SALT_LEN)
	if _, err := io.ReadFull(rand.Reader, salt_); err != nil {
		log.Fatalf("aesgsmEncryption : Salt Reading Error %v\n", err)
	}

	gcmBlock, nonce_len_, _ := cryptoSetup(salt_)

	nonce := make([]byte, nonce_len_)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        log.Fatalf("aesgsmEncryption : Nonce Reading Error %v\n", err)
    }

	cipher := gcmBlock.Seal(nonce, nonce, plain_text, nil)
	cipher_text := append(salt_, cipher...)
	return []byte(cipher_text)
}

func aesgcmDecryption(cipher_text []byte) []byte {

	// log.Printf("nonce_len %T %v", nonce_len, nonce_len)
	salt_ := cipher_text[:SALT_LEN]
	gcmBlock, nonce_len_, _ := cryptoSetup(salt_)
	plain_text, err := gcmBlock.Open(nil, cipher_text[SALT_LEN:SALT_LEN + nonce_len_], cipher_text[SALT_LEN + nonce_len_:], nil)
	if err != nil {
		log.Fatalf("aesgcmDecryption : Decryption Failed -> %v\n", err)
	}

	return []byte(plain_text)
}

func cryptoSetup(salt_ []byte) (cipher.AEAD, int, int) {

    key := pbkdf2.Key([]byte(passPhrase), salt_, 4096, 32, sha1.New)

    aes_, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalf("cryptoSetup : Error creating AES -> %v\n", err)
    }

    aesgcmBlock, err := cipher.NewGCM(aes_)
    if err != nil {
        log.Fatalf("cryptoSetup : Error creating AES GSM Block -> %v\n", err)
    }

	nonce_len := aesgcmBlock.NonceSize()
	over_head := aesgcmBlock.Overhead()
	return aesgcmBlock, nonce_len, over_head
}

func main(){
	listen_port_ptr = getopt.String('l', "8989", "The string to match in the message payload")
	key_file_ptr = getopt.String('p', "", "The string to match in the message payload")
	getopt.Parse()


	if len(getopt.Args()) > 0{
		filter_input_array := getopt.Args()
		dst_ip = filter_input_array[0]
		dst_port = filter_input_array[1] 
	} else{
		log.Fatalf("Main Error : The destination ip and port not given as arguments\n")
	}

	var err1 error
	passPhrase, err1 = os.ReadFile(*key_file_ptr)
	if err1 != nil{
		log.Fatalf("Main Error : No such file -> %v\n", *key_file_ptr)
	}

	passPhrase = passPhrase[0:len(passPhrase)-1]

	if getopt.IsSet('l'){
		log.Println("This is server")
		serverSideSetup()
		
	} else{
		log.Println("This is client")
		clientSideSetup()
	}
}
