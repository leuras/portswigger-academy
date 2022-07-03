# Method-based access control can be circumvented

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

## Definition

The front-end restrict access based on the URL and HTTP method. Some web sites are tolerant of alternate HTTP request methods when performing an action. If an attacker can use the GET (or another) method to perform actions on a restricted URL, then they can circumvent the access control that is implemented at the platform layer.

## Notes

Change user endpoint:
```http
POST /admin-roles?username=wiener&action=upgrade
```

The server restricts resquests to this endpoint from user `admin` using `POST` method.
Changing HTTP method to `PUT or GET` will work fine for any user.
```http
PUT /admin-roles?username=wiener&action=upgrade
```
