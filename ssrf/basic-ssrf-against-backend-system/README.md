# Basic SSRF against another back-end system

[Lab in PortSwigger](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)

## Definition
Another type of trust relationship that often arises with server-side request forgery is where the application server is able to interact with other back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses. Since the back-end systems are normally protected by the network topology, they often have a weaker security posture. In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.

In the preceding example, suppose there is an administrative interface at the back-end URL https://192.168.0.68/admin. Here, an attacker can exploit the SSRF vulnerability to access the administrative interface by submitting the following request:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

## Notes
1. Intercept the Check Stock request and change the `stockApi` parameter to `http://192.168.0.1:8080/admin?productId=1&storeId=1`
2. Send this request to Intruder and mark the last IP octect as variable
3. Define the payload type as a number from 1 to 255 and start the attack
4. Look for a 200 status code and send it to Repeater
5. Change the `stockApi` parameter to the delete user link

## Key Words
> ssrf