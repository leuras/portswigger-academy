# Referer-based access control

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-referer-based-access-control)

## Definition
 Some websites base access controls on the Referer header submitted in the HTTP request. The Referer header is generally added to requests by browsers to indicate the page from which a request was initiated.

For example, suppose an application robustly enforces access control over the main administrative page at /admin, but for sub-pages such as /admin/deleteUser only inspects the Referer header. If the Referer header contains the main /admin URL, then the request is allowed.

In this situation, since the Referer header can be fully controlled by an attacker, they can forge direct requests to sensitive sub-pages, supplying the required Referer header, and so gain unauthorized access. 

## Notes
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
...
Referer: https://ac5a1faf1f3d4313c0e79c8d00570050.web-security-academy.net/admin
```

## Key Words
> referer, privilege, escalation