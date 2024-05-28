package main

import (
	"certification_center/rsa"
	"certification_center/tcp"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
)

type Certificate struct {
	Signature *big.Int `json:"signature"`
	Domain    string   `json:"domain"`
	ExpiresIn string   `json:"expiresIn"`
}

func main() {
	domain := "app1.com"
	rsaService := rsa.New()

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

	// Отправка сообщения УЦ
	fmt.Println("Отправка сообщения УЦ...")
	err = serverTCPServer.Send([]byte(domain))
	if err != nil {
		fmt.Println("Ошибка при отправке УЦ:", err)
		return
	}

	// Получение сертификата от УЦ
	fmt.Println("Ожидание сертификата от УЦ...")
	certificateBytes, err := serverTCPServer.Read()
	if err != nil {
		fmt.Println("Ошибка при чтении сертификата:", err)
		return
	}
	var certificate Certificate
	if err = json.Unmarshal(certificateBytes, &certificate); err != nil {
		fmt.Println("ошибка десериализации сертификата: %v", err)
		return
	}
	domainExpiresIn := domain + certificate.ExpiresIn
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
	decSignature := rsaService.DecryptByPublicKey(certificate.Signature, &serverPublicKey)
	if domainExpiresInHashBigInt.Cmp(decSignature) != 0 {
		fmt.Println("Cертификат недействителен")
		return
	}

	listener, err := net.Listen("tcp", ":8005")
	if err != nil {
		fmt.Println("Ошибка запуска УЦ:", err)
	}
	defer listener.Close()

	fmt.Println("Приложение запущено. Ожидание подключений...")

	for {
		clientConn, err := listener.Accept()
		clientTCP, _ := tcp.NewTCPHost(clientConn)
		if err != nil {
			fmt.Println("Ошибка при принятии подключения:", err)
			continue
		}

		go func(clientTCP *tcp.TCPHost) {
			defer clientTCP.Close()

			serializedCertificate, err := json.Marshal(certificate)
			if err != nil {
				fmt.Println("ошибка сериализации сертифика: %v", err)
				return
			}
			err = clientTCP.Send(serializedCertificate)
			if err != nil {
				fmt.Println("Ошибка при отправке сертификата клиенту:", err)
				return
			}
			fmt.Println("Сертификат отправлен клиенту.")
		}(clientTCP)

	}
}
