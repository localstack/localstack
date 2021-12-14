# Advanced topics

## Using custom SSL certificates

To use your own SSL certificate instead of the randomly generated certificate, you can place a file `server.test.pem` into the LocalStack temporary directory (`$TMPDIR/localstack`, or `/tmp/localstack` by default). The file `server.test.pem` must contain the key file, as well as the certificate file content:

```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

## Using custom SSL certificates with docker-compose

Typically, with docker-compose you can add into docker-compose.yml this volume to the LocalStack services:

```
  volumes:
    - "${PWD}/ls_tmp:/tmp/localstack"
    - "/var/run/docker.sock:/var/run/docker.sock"
```

The local directory `/ls_tmp` must contains the three files (server.test.pem, server.test.pem.crt, server.test.pem.key)
