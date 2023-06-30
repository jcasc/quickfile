# quickfile
Quickfile is a minimalist HTTPS fileserver serving a single directory.

## Usage
```quickfile path```

starts the fileserver serving `path` using default settings.
The server displays a random-generated password in the terminal, which is queried via Basic Auth.
The user name provided by the client can be chosen freely but is logged.

## Supported flags

`-p 12345` sets the Port (42777 by default).

`-cert fullchain.pem -key privkey.pem` specifies a X509 cert to use for TLS.
If no cert+key is specified, a self-signed dummy cert with only "quickfile" as subject information is used instead. HTTP without TLS is not supported.



