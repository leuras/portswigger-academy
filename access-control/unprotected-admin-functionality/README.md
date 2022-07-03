# Unprotected admin functionality

[Lab](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

## Recognition

```bash
export TARGET=https://ace11f431ffded74c02746fe00b60073.web-security-academy.net
```

```bash
gobuster -e -u $TARGET -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
```

