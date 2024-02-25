package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const QUICKFILE_VERSION = "v0.6.1"

const UPLOAD_SITE_HTML = `<!DOCTYPE html>
<html>
<title>Quickfile Upload</title>
<body>
<form method="post" id="userfileForm" onsubmit="submitForm(); return false;">
  <input name="userfile" type="file" id="userfileField" required multiple> 
  <button id="userfileButton">Send</button>
</form>
<div id="progress"></div>
<script>
function submitForm() {
	const files = document.getElementById("userfileField").files;
	document.getElementById("userfileButton").disabled = true;
	document.getElementById("userfileField").disabled = true;
	for (let i = 0; i < files.length; i++) {
		const prog = document.createElement("div");
		prog.id = "progress"+i
		document.getElementById("progress").append(prog)
		const xhr = new XMLHttpRequest();
		xhr.upload.onprogress = (event) => {
			document.getElementById("progress"+i).innerHTML = files[i].name + ": " + Math.ceil(event.loaded/(1024)) + " KB";
		};
		xhr.onload = () => {
			document.getElementById("progress"+i).innerHTML = files[i].name + ": " + xhr.status;
		}
		xhr.open("PUT", "/upload/?filename="+files[i].name);
		xhr.send(files[i]);
	}
}
</script>
</body>
</html>
`

func randomPass() string {
	const glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXZYabcdefghijklmnopqrstuvwxyz0123456789-_$."
	const N = 24
	cutoff := byte(255 - 256%len(glyphs))
	rndbuf, buf := make([]byte, N), make([]byte, N)
	for i, j := 0, N; i < N; j++ {
		if j >= N {
			if n, err := rand.Read(rndbuf); err != nil || n != N {
				log.Fatalf("RNG error: %v", err) // should never happen
			}
			j = 0
		}
		if rndbuf[j] <= cutoff {
			buf[i] = glyphs[int(rndbuf[j])%len(glyphs)]
			i++
		}
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
	if len(os.Args) >= 2 && os.Args[1] == "-v" || os.Args[1] == "--version" {
		fmt.Printf("quickfile %v\n", QUICKFILE_VERSION)
		os.Exit(0)
	}
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

var req_usr struct{}

func withUser(r *http.Request, usr string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), req_usr, usr))
}

func getUser(r *http.Request) string {
	return r.Context().Value(req_usr).(string)
}

func authHandler(handler http.Handler, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, pw, ok := r.BasicAuth()
		if !(ok && pw == pass) {
			if ok {
				log.Printf("%v %v %v %v AUTH REJECT USER --> %v", r.RemoteAddr, r.Method, r.URL, usr, http.StatusUnauthorized)
			} else {
				log.Printf("%v %v %v AUTH NOT OK --> %v", r.RemoteAddr, r.Method, r.URL, http.StatusUnauthorized)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			handler.ServeHTTP(w, withUser(r, usr))
		}
	})
}

func fileHandler(dir, pass, prefix string) http.Handler {
	log.Printf("served directory: %v", dir)
	fhandler := http.StripPrefix(prefix, http.FileServer(http.Dir(dir)))
	return authHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%v %v %v %v > delegating to FilServer", r.RemoteAddr, r.Method, r.URL, getUser(r))
		fhandler.ServeHTTP(w, r)
	}), pass)
}

func readToFile(path string, body io.Reader) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("error creating file %v: %w", path, err)
	}

	n, err := io.Copy(f, body)
	if err != nil {
		err = fmt.Errorf("error copying into %v: %w", path, err)
	}

	if err_ := f.Close(); err_ != nil {
		err = errors.Join(err, fmt.Errorf("error while closing %v: %w", path, err_))
	}

	return n, err
}

func uploadHandler(dir, pass string) http.Handler {
	return authHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet { // GET

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := w.Write([]byte(UPLOAD_SITE_HTML)); err != nil {
				log.Printf("%v %v %v %v > err serving page: %v", r.RemoteAddr, r.Method, r.URL, getUser(r), err)
			} else {
				log.Printf("%v %v %v %v --> %v", r.RemoteAddr, r.Method, r.URL, getUser(r), http.StatusOK)
			}

		} else if r.Method == http.MethodPut { // PUT

			n, err := readToFile(dir+"/"+r.FormValue("filename"), r.Body)
			if err != nil {
				log.Printf("%v %v %v %v --> %v %v", r.RemoteAddr, r.Method, r.URL, getUser(r), http.StatusInternalServerError, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				log.Printf("%v %v %v %v --> %v wrote %v bytes", r.RemoteAddr, r.Method, r.URL, getUser(r), http.StatusOK, n)
			}

		}
	}), pass)
}

func getCert(certfile, keyfile string) (cert tls.Certificate, err error) {
	if certfile == "" {
		if cert, err = getDummyCert(); err != nil {
			err = fmt.Errorf("error loading dummy cert: %w", err)
		}
	} else {
		if cert, err = tls.LoadX509KeyPair(certfile, keyfile); err != nil {
			err = fmt.Errorf("error loading cert key pair: %w", err)
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
	mux.Handle("/download/", fileHandler(params.dir, pass, "/download/"))
	mux.Handle("/upload/", uploadHandler(params.dir, pass))
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

	join := make(chan bool)
	go serve(&srv, join)

	select {
	case <-sigint: // SIGINT received
		shutdown(&srv)
		<-join // wait for serving routine to finish
	case <-join: // serving routine returned on its own
		shutdown(&srv) // make absolutely sure error-state server is shut down
	}
}
