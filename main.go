package main

import (
    "bytes" // Importando a biblioteca bytes
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
)

// Adiciona padding ao plaintext para garantir que ele tenha um tamanho múltiplo do tamanho do bloco.
func pad(plaintext []byte, blockSize int) []byte {
    padding := blockSize - len(plaintext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(plaintext, padtext...)
}

// Remove o padding do texto decifrado.
func unpad(ciphertext []byte) ([]byte, error) {
    length := len(ciphertext)
    if length == 0 {
        return nil, errors.New("ciphertext é inválido")
    }
    padding := int(ciphertext[length-1])
    return ciphertext[:length-padding], nil
}

// Função para cifrar uma mensagem com AES e uma chave de 32 bytes (AES-256).
func encryptAES(key, plaintext []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    plaintext = pad(plaintext, aes.BlockSize)
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Função para decifrar uma mensagem com AES usando uma chave de 32 bytes (AES-256).
func decryptAES(key []byte, cryptoText string) (string, error) {
    ciphertext, _ := base64.StdEncoding.DecodeString(cryptoText)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("ciphertext muito curto")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)

    plaintext, err := unpad(ciphertext)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

func main() {
    key := []byte("thisis32bitlongpassphraseimusing") // chave de 32 bytes
    message := "Esta é uma mensagem secreta!"

    encrypted, err := encryptAES(key, []byte(message))
    if err != nil {
        fmt.Println("Erro ao cifrar:", err)
        return
    }
    fmt.Printf("Mensagem cifrada: %s\n", encrypted)

    decrypted, err := decryptAES(key, encrypted)
    if err != nil {
        fmt.Println("Erro ao decifrar:", err)
        return
    }
    fmt.Printf("Mensagem decifrada: %s\n", decrypted)
}
