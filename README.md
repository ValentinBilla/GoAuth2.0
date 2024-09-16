# GoAuth2.0

<img align="right" width="100px" src="logo.svg" alt="GoAuth2.0 logo"/>

GoAuth2.0 is a simple [OAuth2.0](https://oauth.net/2/) server implementation written in [Go](https://go.dev/).
It does not support the entirety of the [specification](https://datatracker.ietf.org/doc/html/rfc6749) but
rather focuses on the authorization code flow using PKCE (Proof of Key Code Exchange) extension

> [!WARNING]  
> This project was originally created as a school assignment,
> although I do my best to respect security and particularly OWASP recommendations,
> I would not recommend using this server in any serious project.

Following OAuth2.0's updated best practices, some functionalities originally included in the
specification are not present in this project those are the same that won't be in [OAuth2.1](https://oauth.net/2.1/)
- PKCE is required for all OAuth clients using the authorization code flow
- The Implicit grant (response_type=token) is omitted from this specification
- The Resource Owner Password Credentials grant is omitted from this specification
