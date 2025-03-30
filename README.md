# Go JSON Web Key Set Fetcher

This repository contains functionality for periodocally synchronizing a in-memory store of JWKS (JSON Web Key Set) from a authroization server,
and JWT (JSON Web Token) validation middleware using this in-memory store.

## Installation

To install the package, simply run:

```bash
go get github.com/yourusername/jwt-validator
```

## Example
Example use can be seen in main.go

## Key fetching/synchronization
In the oauth2 protocol, the client will receive an access token signed
by an authorization server. This token can then be included in the request header sent to the server.
When the server receives this request, it needs to verify its signature using the public key from the authorization server.
These keys are rotated often, and such the server must reach out the authorization server
periodically to refresh its local key store. This synchronization is handled by the JWTFetcher.

## JWT validation
To start validating JWTs, create a JWTValidator instance with the NewJWTValidator function.
This object holds the in-memory store of JWKS from the fetcher, allowed audiences and valid singing methnods specified by the user.

Passing this validator to the JWTMiddleware function returns a http.HandlerFunc middleware ready to authenticate incoming requests.

### How is the JWTMiddleware created?
The JWTMiddleware function signature is somewhat complex.
It takes a JWTValdiator as input and returns a function that accepts a http.Handler and returns a http.Handerl.
This returned function 




