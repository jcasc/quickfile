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
	const glyphs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-"
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

type params struct {
	dir  string
	port int
	cert string
	key  string
	// pass string
}

func getParams() params {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quickfile [flags] directory")
		flag.PrintDefaults()
	}
	port := flag.Int("p", 42777, "The port to be listened on.")
	cert := flag.String("cert", "", "Path of the certificate file. Must be used in combination with '-key'. "+
		"If not provided, fallback self-signed cert is used.")
	key := flag.String("key", "", "Path of the private key file corresponding to '-cert'.")

	flag.Parse()
	dir := flag.Arg(0)

	if *cert == "" && *key != "" || *cert != "" && *key == "" {
		fmt.Fprint(os.Stderr, "-cert and -key must be used in combination.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if dir == "" {
		fmt.Fprint(os.Stderr, "valid directory required.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	ret, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	} else if !ret.IsDir() {
		fmt.Fprintf(os.Stderr, "%v: not a directory\n", dir)
		os.Exit(1)
	}

	return params{dir, *port, *cert, *key}
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

func getCert(certfile, keyfile string) (cert tls.Certificate, err error) {
	if certfile == "" {
		if cert, err = getDummyCert(); err != nil {
			err = fmt.Errorf("error loading dummy cert: %v", err)
		}
	} else {
		if cert, err = tls.LoadX509KeyPair(certfile, keyfile); err != nil {
			err = fmt.Errorf("error loading cert key pair: %v", err)
		}
	}
	return
}

func main() {
	params := getParams()

	cert, err := getCert(params.cert, params.key)
	if err != nil {
		log.Fatal(err)
	}

	pass := randomPass()
	log.Printf("password: %v", pass)

	favicon, err := getFaviconReader()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", fileHandler(params.dir, pass))
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
		Addr:    fmt.Sprintf(":%v", params.port),
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
