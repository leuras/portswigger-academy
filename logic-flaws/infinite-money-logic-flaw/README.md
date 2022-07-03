# Infinite money logic flaw

(Lab)[https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money]

## Solution

- Use the sign up coupon `SIGNUP30` to buy several gift-cards
- Redeem all git-cards bought in your own account. Your balance will increase
- Use the money to keep buying more gift-cards using `SIGNUP30` coupon
- Do the same thing over and over until reach the desired amount
  