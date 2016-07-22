# Go ASAP

A library that creates and verifies JSON Web Tokens (JWT) for service to service authentication purposes using the Atlassian Service Authentication Protocol (ASAP).

[Atlassian S2S Authentication Protocol (ASAP) - Specification](http://s2sauth.bitbucket.org/)

## Getting Started

### Installing

    go get bitbucket.org/atlassian/go-asap

### Generating key pairs

Use OpenSSL from the command line to generate the key pairs.

    openssl genrsa -out private-key.pem 2048
    openssl rsa -in private-key.pem -pubout > public-key.pem


##Usage

### Client

Instantiate an ASAP object

    asap := asap.NewASAP("service/key", "service", nil)

Setup a key provider in your application's config (or per request, if you want to)

    kp := &keyprovider.FSKeyProvider{
        PrivateKeyPath: "keys/private/service-id/key",
    }

Fetch the key later when you need it

    privateKey, err := kp.GetPrivateKey()

Sign a request!

    token, err := asap.Sign("audience", privateKey)
    if err != nil {
        log.Error(err)
    }
    request.Header = r.Header
    request.Header.Set("Authorization", "Bearer "+string(token))

And then make your request with net/http as normal!


### Server

This assumes you're using `github.com/codegangsta/negroni` for middleware.

Instantiate the ASAP middleware

    &middleware.ASAPMiddleware{
        ASAP: &asap.ASAP{
            ServiceID:          "audience",
            AuthorisedSubjects: []string{"service"},
        },
        PublicKeyProvider: &keyprovider.FSKeyProvider{
            PublicKeyDir: "keys/public",
        },
        AuthenticationRules: []middleware.Rule{
            middleware.Rule{
                Regexp:  regexp.MustCompile("/api/.*"),
                Clients: mapset.NewSet("service"),
            },
        },
    }

Done!
