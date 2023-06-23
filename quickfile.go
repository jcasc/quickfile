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

func randomPass() string {
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

func getParams() (string, string) {

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

	return *dir, addr
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

func fileHandler(dir string) http.HandlerFunc {
	fhandler := http.FileServer(http.Dir(dir))
	pass := randomPass()
	log.Printf("served directory: %v", dir)
	log.Printf("random pass: %v", pass)

	// objects are poor man's closures
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, pw, ok := r.BasicAuth()
		log.Printf("%v %v %v", r.RemoteAddr, usr, r.RequestURI)
		if ok && pw == pass {
			fhandler.ServeHTTP(w, r)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

func main() {

	dir, addr := getParams()

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)

	cert, err := getDummyCert()
	if err != nil {
		log.Fatal(err)
	}

	srv := http.Server{
		Addr:    addr,
		Handler: fileHandler(dir),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	join := make(chan bool, 1)
	go serve(&srv, join)

	select {
	case <-sigint: // SIGINT received
		shutdown(&srv)
		<-join // wait for serving routine to finish
	case <-join: // serving routine returned on its own
		shutdown(&srv) // make absolutely sure error-state server is shut down
	}
}
