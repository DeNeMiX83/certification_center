package main

import (
	"certification_center/rsa"
	"certification_center/tcp"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Certificate struct {
	Signature *big.Int `json:"signature"`
	Domain    string   `json:"domain"`
	ExpiresIn string   `json:"expiresIn"`
}

func main() {
	rsaServise := rsa.New()

	fmt.Println("Подключение к приложению...")
	appConn, err := net.Dial("tcp", "localhost:8005")
	if err != nil {
		fmt.Println("Ошибка при подключении к приложению:", err)
		return
	}
	fmt.Println("Подключение к приложению успешно.")
	appTCPapp, _ := tcp.NewTCPHost(appConn)
	defer appConn.Close()

	// Получение сертификата от сервера
	fmt.Println("Ожидание сертификата от сервера...")
	certificateBytes, err := appTCPapp.Read()
	if err != nil {
		fmt.Println("Ошибка при чтении сертификата:", err)
		return
	}
	var certificate Certificate
	if err = json.Unmarshal(certificateBytes, &certificate); err != nil {
		fmt.Println("ошибка десериализации сертификата: %v", err)
		return
	}

	fmt.Println("Подключение к УЦ...")
	serverConn, err := net.Dial("tcp", "localhost:8004")
	if err != nil {
		fmt.Println("Ошибка при подключении к УЦ:", err)
		return
	}
	fmt.Println("Подключение к УЦ успешно.")
	serverTCPServer, _ := tcp.NewTCPHost(serverConn)
	defer serverConn.Close()

	serverPublicKeyBytes, err := serverTCPServer.Read()
	if err != nil {
		fmt.Println("ошибка чтения публичного ключа УЦ: %v", err)
	}
	var serverPublicKey rsa.PublicKey
	err = json.Unmarshal(serverPublicKeyBytes, &serverPublicKey)
	if err != nil {
		fmt.Println("ошибка десериализации публичного ключа УЦ: %v", err)
	}
	fmt.Println("Публичный ключ УЦ получен.")

	expiresInTime, err := time.Parse("2006-01-02 15:04:05", certificate.ExpiresIn)
	if err != nil {
		fmt.Println("Ошибка при преобразовании строки в time.Time:", err)
		return
	}

	now := time.Now()
	if expiresInTime.Before(now) {
		fmt.Println("Время жизни сертификата истекло")
	}

	domainExpiresIn := certificate.Domain + certificate.ExpiresIn
	domainExpiresInHash, err := rsa.HashSHA256(domainExpiresIn)
	if err != nil {
		fmt.Println("Ошибка при хешировании: %v", err)
	}
	domainExpiresInHashBigInt := new(big.Int)
	_, ok := domainExpiresInHashBigInt.SetString(domainExpiresInHash, 16)
	if !ok {
		fmt.Println("Ошибка при преобразовании hash строки в *big.Int")
		return
	}
	decSignature := rsaServise.DecryptByPublicKey(certificate.Signature, &serverPublicKey)
	if domainExpiresInHashBigInt.Cmp(decSignature) != 0 {
		fmt.Println("Cертификат недействителен")
		return
	} else {
		fmt.Println("Cертификат действителен")
		return
	}
}
