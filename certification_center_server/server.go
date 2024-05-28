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
	serverPublicKey, serverPrivateKey := rsaServise.GenerateKeys(512)

	listener, err := net.Listen("tcp", ":8004")
	if err != nil {
		fmt.Println("Ошибка запуска УЦ:", err)
	}
	defer listener.Close()

	fmt.Println("УЦ запущен. Ожидание подключений...")
	for {
		clientConn, err := listener.Accept()
		clientTCP, _ := tcp.NewTCPHost(clientConn)
		if err != nil {
			fmt.Println("Ошибка при принятии подключения:", err)
			continue
		}

		go func(clientTCP *tcp.TCPHost) {
			defer clientTCP.Close()

			fmt.Println("Новое подключение...")

			serializedKey, err := json.Marshal(serverPublicKey)
			if err != nil {
				fmt.Println("ошибка сериализации публичного ключа: %v", err)
			}
			err = clientTCP.Send(serializedKey)
			if err != nil {
				fmt.Println("ошибка отправки публичного ключа клиента: %v", err)
			}
			fmt.Println("Отправка публичного ключа клиенту")

			fmt.Println("Ожидание домена от клиента...")
			domainBytes, err := clientTCP.Read()
			if err != nil {
				fmt.Println("Ошибка чтения сообщения:", err)
				return
			}
			domain := string(domainBytes)
			fmt.Println("Домен от клиента получен.", domain)

			now := time.Now()
			oneYearLater := now.Add(24 * time.Hour * 365)
			expiresInStr := oneYearLater.Format("2006-01-02 15:04:05")
			domainExpiresIn := domain + expiresInStr
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
			signature := rsaServise.EncryptByPrivateKey(domainExpiresInHashBigInt, serverPrivateKey)
			cert := &Certificate{
				Signature: signature,
				Domain:    domain,
				ExpiresIn: expiresInStr,
			}

			serializedCert, err := json.Marshal(cert)
			if err != nil {
				fmt.Println("ошибка сериализации сертификата: %v", err)
				return
			}
			err = clientTCP.Send(serializedCert)
			if err != nil {
				fmt.Println("Ошибка при отправке сертификата:", err)
				return
			}
			fmt.Println("Сертификат отправлен клиенту.")

		}(clientTCP)
	}
}
