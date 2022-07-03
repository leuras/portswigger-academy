# User ID controlled by request parameter

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

## Definition
 Horizontal privilege escalation arises when a user is able to gain access to resources belonging to another user, instead of their own resources of that type. For example, if an employee should only be able to access their own employment and payroll records, but can in fact also access the records of other employees, then this is horizontal privilege escalation.

Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. For example, a user might ordinarily access their own account page using a URL like the following:
```http
https://insecure-website.com/myaccount?id=123
```
Now, if an attacker modifies the id parameter value to that of another user, then the attacker might gain access to another user's account page, with associated data and functions. 

## Notes

User account URL
```http
/my-account?id=<username>
```

Logged in as wiener:
```http
GET /my-account?id=carlos
```
Carlos API Key: `XY7UkGP1YlpO21fLoVhiIofSlT1zRsmf`

## Key Words

> id, idor, userid