# User ID controlled by request parameter, with unpredictable user IDs

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

## Definition
In some applications, the exploitable parameter does not have a predictable value. For example, instead of an incrementing number, an application might use globally unique identifiers (GUIDs) to identify users. Here, an attacker might be unable to guess or predict the identifier for another user. However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews. 

## Notes

Carlos blog page link:
```http
https://ac051f2a1e904400c0a835d1000f0037.web-security-academy.net/blogs?userId=71f8109c-ff88-44c1-971f-028552156937
```
Carlos GUID is `71f8109c-ff88-44c1-971f-028552156937`

## Key Words

> id, idor, guid, uuid, userid
