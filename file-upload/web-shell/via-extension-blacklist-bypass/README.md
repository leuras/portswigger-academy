# Web shell upload via extension blacklist bypass

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

## Definition
As we discussed in the previous section, servers typically won't execute files unless they have been configured to do so. For example, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their /etc/apache2/apache2.conf file:
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .php
```

Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings. Apache servers, for example, will load a directory-specific configuration from a file called .htaccess if one is present.

Similarly, developers can make directory-specific configuration on IIS servers using a web.config file. This might include directives such as the following, which in this case allows JSON files to be served to users:
```xml
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```

Web servers use these kinds of configuration files when present, but you're not normally allowed to access them using HTTP requests. However, you may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type. 

## Notes
Firstly, craft a `.htaccess` file that instructs Apache to handle a file extension as a PHP file and upload it to the server. If it's don't work, considere this approach (here)[https://thibaud-robin.fr/articles/bypass-filter-upload/]. With this new setup, just upload the exploit file with the custom file extension and enjoy.

## Key Words
> file upload, web shell, rce, remote config, htaccess, bypass