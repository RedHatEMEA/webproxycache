#!/usr/bin/python

import OpenSSL.crypto
import os


def sn():
    try:
        sn = int(open("certs/sn").read())
    except IOError:
        sn = 1

    open("certs/sn", "w").write("%u\n" % (sn + 1))
    return sn


def make_ca_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

    cert = OpenSSL.crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(sn())
    cert.get_subject().CN = "Webcache CA"
    cert.gmtime_adj_notBefore(-60 * 60)
    cert.gmtime_adj_notAfter((365 * 24 - 1) * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.add_extensions([
        OpenSSL.crypto.X509Extension("basicConstraints", False, "CA:TRUE"),
        OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash",
                                     subject=cert),
    ])
    cert.sign(key, "sha1")

    with os.fdopen(os.open("certs/ca.key", os.O_WRONLY | os.O_CREAT, 0600),
                   "w") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                               key))
    with open("certs/ca.crt", "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                cert))


def make_cert(cn):
    ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                              open("certs/ca.crt").read())
    ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                            open("certs/ca.key").read())

    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

    cert = OpenSSL.crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(sn())
    cert.get_subject().CN = cn
    cert.gmtime_adj_notBefore(-60 * 60)
    cert.gmtime_adj_notAfter((365 * 24 - 1) * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, "sha1")

    with os.fdopen(os.open("certs/%s.key" % cn, os.O_WRONLY | os.O_CREAT, 0600),
                           "w") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                               key))
    with open("certs/%s.crt" % cn, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                cert))


try:
    os.mkdir("certs")
    make_ca_cert()
except OSError:
    pass
