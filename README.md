# Main features

**d4-pyclient** is python implemention of the [D4 encapsulation
protocol](https://github.com/D4-project/architecture/tree/master/format). 

It is a low-barrier entry for anyone interested into tinkering with the D4
protocol or embedding a d4 client into another project. It supports both regular
types and types defined by meta-header.

# Launching

```shell
./d4-pyclient.py -h
usage: d4-pyclient.py [-h] -c CONFIG [-cc]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config directory
  -cc, --check_certificate
                        check server certificate
```

# Configuration Files

 of the client configuration can be stored in folder containing the following files:

 - key: your Pre-Shared-Key
 - snaplen: default is 4096
 - source: stdin or d4server
 - destination: stdout, [fe80::ffff:ffff:ffff:a6fb]:4443, 127.0.0.1:4443
 - type: D4 packet type, see [types](https://github.com/D4-project/architecture/tree/master/format)
 - uuid: generated automatically if empty
 - version: protocol version
 - rootCA.crt: optional : CA certificate to check the server certificate
 - metaheader.json: optional : a json file describing feed's meta-type [types](https://github.com/D4-project/architecture/tree/master/format)
