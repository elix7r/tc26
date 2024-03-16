package main

import (
	"log"
	"net"
	"net/http"
)

const (
	host = ""
	port = "8080"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", ServeHTTP)

	srv := http.Server{
		Addr:    net.JoinHostPort(host, port),
		Handler: mux,
	}

	key := generateTC26Key("key.pem")

	generateCert(key.Public(), key, "cert.pem")

	log.Printf("server start on http://%s:%s", host, port)
	log.Fatalln(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}

func ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	method := request.Method

	_, err := writer.Write([]byte(method))
	if err != nil {
		panic(err)
	}
}
