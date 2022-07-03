# Lab: Insufficient workflow validation

(Lab)[https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation]

## Solution

1. Turn on `Intercept Server Response`
2. Add the product in the cart
3. Place order with `POST /cart/checkout`
4. On server response, override response to `GET /cart/order-confirmation?order-confirmation=true`