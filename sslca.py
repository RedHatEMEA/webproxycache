#!/usr/bin/python

import OpenSSL.crypto
import os
import random


class CA(object):
    ROOT = "certs"

    def __init__(self):
        try:
            os.mkdir(self.ROOT)
        except OSError:
            pass

        cn = "Webcache CA " + "".join(random.choice("0123456789ABCDEF") for i in range(8))
        self.ca_key = self.get_key(self.ROOT + "/ca.key")
        self.ca_cert = self.get_cert(self.ROOT + "/ca.crt", self.ca_key, cn,
                                     True)

    def sn(self):
        try:
            sn = int(open(self.ROOT + "/sn").read())
        except IOError:
            sn = 1

        open(self.ROOT + "/sn", "w").write("%u\n" % (sn + 1))
        return sn

    def get_key(self, filename):
        try:
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                 open(filename).read())
        except IOError:
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

            with os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, 0600),
                           "w") as f:
                f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                       key))
        return key

    def get_cert(self, filename, key, cn, ca=False):
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                   open(filename).read())
        except IOError:
            cert = OpenSSL.crypto.X509()
            cert.set_version(2)
            cert.set_serial_number(self.sn())
            cert.get_subject().CN = cn
            cert.gmtime_adj_notBefore(-60 * 60)
            cert.gmtime_adj_notAfter((365 * 24 - 1) * 60 * 60)
            cert.set_pubkey(key)
            if ca:
                cert.set_issuer(cert.get_subject())
                cert.add_extensions([
                    OpenSSL.crypto.X509Extension("basicConstraints", False,
                                                 "CA:TRUE"),
                    OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False,
                                                 "hash", subject=cert),
                ])
            else:
                cert.set_issuer(self.ca_cert.get_subject())
            cert.sign(self.ca_key, "sha1")

            with open(filename, "w") as f:
                f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                        cert))
        return cert

    def get_key_cert(self, cn):
        key = self.get_key(self.ROOT + "/%s.key" % cn)
        cert = self.get_cert(self.ROOT + "/%s.crt" % cn, key, cn)
        return (key, cert)
