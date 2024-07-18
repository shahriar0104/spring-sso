# spring-sso
## Instruction to test SSO
1. First run the `spring-oauth-server`
2. Run `spring-resource-server`, `spring-oauth-client`, `spring-oauth-client-2`
3. Go to `http://127.0.0.1:8082/message`. Which is an endpoint of `spring-oauth-client`.
4. It will require you to login. Login with username: `admin`, and password: `admin` to access the resource.
5. Go to `http://127.0.0.1:8083/message`. Which is an endpoint of `spring-oauth-client-2` having different client-id and secret than the `spring-oauth-client`.
6. But it won't require you to login again. You will be able to get the resource without login.

## Note
Somehow this flow does not work if you don't have the `spring-oauth-server` running in a different host than the clients. That's why you will find the host in the server address of `spring-oauth-server` is given `localhost` and the clients and resource server are given `127.0.0.1`.
