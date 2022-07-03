# Remote code execution via web shell upload

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)

## Definition
If you're able to successfully upload a web shell, you effectively have full control over the server. This means you can read and write arbitrary files, exfiltrate sensitive data, even use the server to pivot attacks against both internal infrastructure and other servers outside the network. For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:
```php 
<?php echo file_get_contents('/path/to/target/file'); ?>
```
Once uploaded, sending a request for this malicious file will return the target file's contents in the response. 

## Notes
To exploit this flaw, just upload `exploit.php` in avatar upload form field and then do a GET request to this file to see the contents.

## Key Words
> file upload, web shell, rce