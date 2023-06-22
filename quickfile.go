package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func random_pw() string {
	const glyphs = "abcdefghijk-mnopqrstuvwxyzABCDEFGH-JKLMN-PQRSTUVWXYZ-123456789--"
	const N = 32
	buf := make([]byte, N)
	if n, err := rand.Read(buf); err != nil || n != N {
		log.Fatalf("RNG error: %v", err)
	}
	for i := 0; i < N; i++ {
		buf[i] = glyphs[buf[i]%64]
	}
	return string(buf)
}

func get_params() (string, string, string) {

	dir := flag.String("d", "", "The directory to be served")
	port := flag.Int("p", 42777, "The port to be listened on")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "valid directory required. see --help")
		os.Exit(1)
	}
	if _, err := os.Stat(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "not a valid directory: %v\n", *dir)
		os.Exit(1)
	}

	addr := ":" + fmt.Sprint(*port)

	rnd_pw := random_pw()
	log.Printf("random Password: %v", rnd_pw)

	return *dir, addr, rnd_pw
}

func serve(srv *http.Server, done chan bool) {
	log.Printf("listening on: %v", srv.Addr)
	log.Printf("%v", srv.ListenAndServeTLS("", ""))
	done <- true
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func main() {

	dir, addr, rnd_pw := get_params()

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)

	cert, err := getDummyCert()
	if err != nil {
		log.Fatal(err)
	}

	fhandler := http.FileServer(http.Dir(dir))
	srv := http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			usr, pw, ok := r.BasicAuth()
			log.Printf("%v %v %v", r.RemoteAddr, usr, r.RequestURI)
			if ok && pw == rnd_pw {
				fhandler.ServeHTTP(w, r)
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	join := make(chan bool, 1)
	go serve(&srv, join)

	select {
	case <-sigint: // SIGINT received
		shutdown(&srv)
		<-join // wait for serve routine to finish
	case <-join: // server returned on its own
		shutdown(&srv) // might free some resources or handle error-state server somehow
	}
}
