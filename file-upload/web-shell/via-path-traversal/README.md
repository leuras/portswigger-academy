# Web shell upload via path traversal

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)

## Definition
 While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net.

As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:

```http
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com


HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 39

<?php echo system($_GET['command']); ?>
```

This behavior is potentially interesting in its own right, as it may provide a way to leak source code, but it nullifies any attempt to create a web shell.

This kind of configuration often differs between directories. A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all. 

## Notes
To solve this lab, intercept the POST request and change the filename to `../exploit.php`. These change will make the server save the file in `/files` folder, not `/files/avatars` and it will be evaluated as a regular PHP file.

## Key Words
> file upload, web shell, path traversal, rce