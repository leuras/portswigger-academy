# Multi-step process with no access control on one step

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

## Definition
Sometimes, a web site will implement rigorous access controls over some of these steps, but ignore others. For example, suppose access controls are correctly applied to the first and second steps, but not to the third step. Effectively, the web site assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. Here, an attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

## Notes
How is the best way to find hidden URLs? Pages that isn't linked by public or unprotected pages?

Solution:
```http
POST /admin-roles HTTP/1.1
Host: ace41f821f698db8c04d2e04007b004d.web-security-academy.net
Cookie: session=2UU2coBwzgtjhzBIAYRT0omEAuAthuop
...
Connection: close

username=wiener&action=upgrade&confirmed=true
```

## Key Words
> discovery, page, access control, unprotected