# Authentication bypass via flawed state machine

(Lab)[https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine]

## Solution

- Firstly, turn on `Intercept Server Response`
- Call `POST /login`
- Drop off the server redirect `GET /role-selector`. This URL changes the default role for user session
- Request `GET /admin`