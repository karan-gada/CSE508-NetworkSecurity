package main
import(
	"golang.org/x/crypto/pbkdf2"
	"crypto/aes"
    "crypto/sha1"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "os"
    // "strings"
    // "bytes"
)

var(
    flag_val *bool
)

func main(){
    val_for_flag := false
    flag_val = &val_for_flag
    fmt.Printf("%v %v %v\n", flag_val, *flag_val, val_for_flag)

    fh_,err := os.ReadFile("key_File")
    fmt.Println(len(fh_))
    fh_ = fh_[0:len(fh_)-1]
    fmt.Println(len(fh_))
    fmt.Println(string(fh_))
    

	text := []byte("My Super Secret Code Stuff sdifusdfoishadoihg")
    pw := []byte("passphrasewhichneedstobe32bytes!")

    key := pbkdf2.Key([]byte(pw), nil, 4096, 32, sha1.New)

	fmt.Printf("The length of plain text %v and key %v\n", len(text), len(key))

    c, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(c.BlockSize())

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        fmt.Println(err)
    }
    fmt.Printf("%T\n", gcm)
    // creates a new byte array the size of the nonce
    // which must be passed to Seal
    nonce := make([]byte, gcm.NonceSize())
	fmt.Printf("The nounce size is %v and max diff is %v\n", len(nonce), gcm.Overhead())
    // populates our nonce with a cryptographically secure
    // random sequence
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        fmt.Println(err)
    }

    // here we encrypt our text using the Seal function
    // Seal encrypts and authenticates plaintext, authenticates the
    // additional data and appends the result to dst, returning the updated
    // slice. The nonce must be NonceSize() bytes long and unique for all
    // time, for a given key.
	cipher_text :=gcm.Seal(nonce, nonce, text, nil)
    fmt.Printf("The cipher text is %T %v and nonce now is %v\n", cipher_text, len(cipher_text), len(nonce))
    fmt.Printf("%p %p\n", cipher_text, nonce)

    block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

    nonce_len := aesgcm.NonceSize()
    fmt.Println(nonce_len)

	plaintext, err := aesgcm.Open(nil, cipher_text[0:nonce_len], cipher_text[nonce_len:], nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)

    fmt.Println(append([]int{2,36,23} , []int{32,325,13}...))
    
}