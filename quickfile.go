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
		log.Fatalf("RNG error: %v", err) // should never happen
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

	return *dir, fmt.Sprint(*port)
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

func fileHandler(dir, pass string) http.HandlerFunc {
	fhandler := http.FileServer(http.Dir(dir))
	log.Printf("served directory: %v", dir)

	// objects are poor man's closures
	handler := func(w http.ResponseWriter, r *http.Request) {
		usr, pw, ok := r.BasicAuth()

		if !(ok && pw == pass) {
			if ok {
				log.Printf("%v %v AUTH REJECT USER %v", r.RemoteAddr, r.URL, usr)
			} else {
				log.Printf("%v %v AUTH NOT OK", r.RemoteAddr, r.URL)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			log.Printf("%v %v AUTH ACCEPT USER %v", r.RemoteAddr, r.URL, usr)
			fhandler.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(handler)
}

func main() {
	dir, port := getParams()
	pass := randomPass()
	log.Printf("password: %v", pass)

	cert, err := getDummyCert()
	if err != nil {
		log.Fatal(err)
	}

	favicon, err := getFaviconReader()
	if err != nil {
		log.Print(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", fileHandler(dir, pass))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		if favicon == nil {
			log.Printf("%v %v 404", r.RemoteAddr, r.URL)
			http.NotFound(w, r)
		} else {
			log.Printf("%v %v", r.RemoteAddr, r.URL)
			http.ServeContent(w, r, "", time.Time{}, favicon)
		}
	})

	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)

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
