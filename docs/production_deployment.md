## Production Deployments

this is the recommended deployment

| Domain           | Path                                    |                                   |
|------------------|-----------------------------------------|-----------------------------------|
|pki.example.com   |/certificates                            | management portal
|pki.example.com   |/certificates/<id>                       | certificate detail
|pki.example.com   |/certificates/<id>/export/<format>       | certificate export
|certs.example.com |/repository                              | certificate policies homepage
|certs.example.com |/repository/*.crt                        | certificate download link
|certs.example.com |/repository/*.crl                        | certificate revocation link
|ocsp.example.com  |/*                                       | ocsp protocol 
