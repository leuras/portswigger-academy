# Source code disclosure via backup files

[Lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)

## Recognition

```bash
export TARGET=https://ac5b1f111e24dd76c06e4355007a002d.web-security-academy.net
```

```bash
gobuster -e -u $TARGET -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
```

Backup File Found: `ProductTemplate.java.bak`

Database username `postgres`
Database password `d6pudbi7ure0rwhixo0wpzsirbsvfk66`