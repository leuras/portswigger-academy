# Flawed enforcement of business rules

(Lab)[https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules]

## Solution

- There are two coupons: `NEWCUST5` and `SIGNUP30`
- Add the item to the cart and alternate requets for each coupon until the price reaches $0.00
- Enjoy!