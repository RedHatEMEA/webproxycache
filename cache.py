#!/usr/bin/python

import copy
import database
import errno
import httplib
import os
import re
import rfc822
import socket
import SocketServer
import ssl
import sslca
import sys
import tempfile
import threading
import urllib
import urlparse
import zlib


certlock = threading.Lock()
tls = threading.local()


class EOFException(Exception):
    pass


class NotInCacheException(Exception):
    pass


class IO(object):
    def __init__(self, _f):
        self.f = _f
        self.headers = {}

    def log(self, mode, code, line):
        with certlock:
            print >>sys.stderr, "%-4s(%u) %s" % (mode, code, line)

    def readline(self):
        l = self.f.readline()
        if l == "" or l[-1] != "\n":
            raise EOFException()
        return l.strip()

    def read(self, n):
        return self.f.read(n)

    def write(self, s):
        self.f.write(s)

    def flush(self):
        self.f.flush()

    def copyall(self, dst, extra=None):
        if self.headers.get("Content-Encoding", "") == "gzip":
            d = zlib.decompressobj(31)

        while True:
            data = self.read(4096)
            if data == "":
                break

            dst.write(data)
            if extra:
                if self.headers.get("Content-Encoding", "") == "gzip":
                    extra.write(d.decompress(data))
                else:
                    extra.write(data)

    def copylength(self, dst, n, extra=None, d=None):
        if self.headers.get("Content-Encoding", "") == "gzip" and d is None:
            d = zlib.decompressobj(31)

        while n > 0:
            data = self.read(min(n, 4096))
            if data == "":
                raise EOFException()

            dst.write(data)
            if extra:
                if self.headers.get("Content-Encoding", "") == "gzip":
                    extra.write(d.decompress(data))
                else:
                    extra.write(data)

            n -= len(data)

    def copychunked(self, dst, extra=None):
        d = None
        if self.headers.get("Content-Encoding", "") == "gzip":
            d = zlib.decompressobj(31)

        while True:
            n = int(self.readline(), 16)
            dst.write("%x\r\n" % n)

            self.copylength(dst, n, extra, d)

            if self.read(2) != "\r\n":
                raise EOFException()

            dst.write("\r\n")

            if n == 0:
                break

    def copybody(self, dst, extra=None):
        if "Content-Length" in self.headers:
            self.copylength(dst, int(self.headers["Content-Length"]), extra)

        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.copychunked(dst, extra)

        else:
            self.copyall(dst, extra)


class Request(IO):
    def __init__(self, _f, netloc=None):
        super(Request, self).__init__(_f)

        (self.verb, self.url, self.http) = self.readline().split(" ", 2)

        if self.verb == "CONNECT":
            self.url = "https://" + self.url

        if netloc:
            self.url = "https://%s:%u" % netloc + self.url

        self.url = urlparse.urlparse(self.url)

        self.headers = rfc822.Message(self.f, False)

    def path(self):
        url = list(self.url)
        url[0] = url[1] = None
        return urlparse.urlunparse(url)

    def netloc(self):
        if ":" in self.url.netloc:
            (host, port) = self.url.netloc.split(":", 1)
            return (host, int(port))
        elif self.url.scheme == "http":
            return (self.url.netloc, 80)
        elif self.url.scheme == "https":
            return (self.url.netloc, 443)
        else:
            raise Exception()


class FakeRequest(Request):
    def __init__(self, _req, _url):
        (self.verb, self.http) = (_req.verb, _req.http)
        self.url = urlparse.urlparse(_url)
        self.headers = copy.copy(_req.headers)
        self.headers["Host"] = self.url.netloc
        del self.headers["Authorization"]


class UncachedResponse(IO):
    def __init__(self, _req):
        super(UncachedResponse, self).__init__(None)

        self.req = _req
        self.make_request(self.req)

        if self.req.verb == "GET" and (re.match("^https://registry-1.docker.io:443/v2/[^/]+/[^/]+/blobs/sha256:[0-9a-z]{64}$", urlparse.urlunparse(self.req.url)) or
                                       re.match("^https://registry.access.redhat.com:443/v1/images/[0-9a-z]{64}/(ancestry|json|layer)$", urlparse.urlunparse(self.req.url)) or
                                       re.match("^https://github.com:443/[^/]+/[^/]+/archive/", urlparse.urlunparse(self.req.url)) or
                                       re.match("^https://rubygems.org:443/gems/", urlparse.urlunparse(self.req.url))):
            (self.http, self.code, self.other) = self.readline().split(" ", 2)
            self.code = int(self.code)
            self.headers = rfc822.Message(self.f, False)

            self.f.close()
            self.s.close()

            self.make_request(FakeRequest(self.req, self.headers["Location"]))

    def make_request(self, req):
        self.s = socket.socket()
        self.s.connect(req.netloc())
        if req.url.scheme == "https":
            self.s = ssl.wrap_socket(self.s, cert_reqs=ssl.CERT_REQUIRED,
                                     ca_certs="/etc/pki/tls/certs/ca-bundle.crt")
            try:
                ssl.match_hostname(self.s.getpeercert(), req.netloc()[0])
            except AttributeError:
                pass

        self.f = self.s.makefile()

        self.write("%s %s %s\r\n" % (req.verb, req.path(), req.http))
        self.write(req.headers)
        self.write("\r\n")

        if req.verb not in ["GET", "HEAD"]:
            req.copybody(self)

        self.flush()

    def cacheable(self):
        return self.req.verb == "GET" and \
            "Range" not in self.req.headers and \
            "Content-Range" not in self.headers and \
            self.headers.get("Content-Encoding", "") in ["", "gzip"] and \
            not self.req.netloc() == ("auth.docker.io", 443)

    def serve(self):
        (self.http, self.code, self.other) = self.readline().split(" ", 2)
        self.code = int(self.code)
        self.headers = rfc822.Message(self.f, False)
        del self.headers["Connection"]

        self.req.write("%s %u %s\r\n" % (self.http, self.code, self.other))
        self.req.write(self.headers)
        self.req.write("Connection: close\r\n")
        self.req.write("\r\n")

        if self.cacheable() and self.code == 200:
            self.log("SAVE", self.code, urlparse.urlunparse(self.req.url))

            cw = CacheWriter(self.req, self)
            self.copybody(self.req, cw)
            cw.persist()

        elif self.cacheable() and self.code in [301, 302, 307, 404]:
            self.log("SAVE", self.code, urlparse.urlunparse(self.req.url))

            cw = CacheWriter(self.req, self)
            self.copybody(self.req)
            cw.persist()

        else:
            self.log("MISS", self.code, urlparse.urlunparse(self.req.url))

            self.copybody(self.req)

        self.req.flush()
        self.f.close()
        self.s.close()


class CacheWriter(IO):
    def __init__(self, _req, _resp):
        super(CacheWriter, self).__init__(tempfile.NamedTemporaryFile())

        (self.req, self.resp) = (_req, _resp)

    def persist(self):
        if self.resp.code == 200:
            hl = ["Content-Type"]
        elif self.resp.code in [301, 302, 307]:
            hl = ["Location"]
        else:
            hl = []

        extraheaders = []
        for k in hl:
            v = self.resp.headers.get(k, None)
            if v:
                extraheaders.append("%s: %s" % (k, v))
        extraheaders = "\r\n".join(extraheaders)

        tls.db.persist(urlparse.urlunparse(self.req.url), self.resp.code,
                       extraheaders, self.f)
        self.f.close()


class CachedResponse(IO):
    def __init__(self, _req):
        super(CachedResponse, self).__init__(None)

        self.req = _req

        if self.req.verb != "GET" or self.req.headers.get("Range"):
            raise NotInCacheException()

        rv = tls.db.serve(urlparse.urlunparse(self.req.url))
        if rv is None:
            raise NotInCacheException()

        (self.code, self.extraheaders, self.f, self.length) = rv

    def serve(self):
        self.log("HIT", self.code, urlparse.urlunparse(self.req.url))

        self.req.write("HTTP/1.1 %u %s\r\n" %
                       (self.code, httplib.responses[self.code]))

        self.req.write("Content-Length: %u\r\n" % self.length)
        if self.extraheaders:
            self.req.write(self.extraheaders + "\r\n")
        self.req.write("Connection: close\r\n")
        self.req.write("\r\n")
        self.copylength(self.req, self.length)

        self.req.flush()


class LocalResponse(IO):
    def __init__(self, _req, fn):
        super(LocalResponse, self).__init__(open(fn))

        self.req = _req

    def serve(self):
        self.log("HIT", 200, urlparse.urlunparse(self.req.url))

        self.req.write("HTTP/1.1 200 OK\r\n")
        self.req.write("Connection: close\r\n")
        self.req.write("\r\n")
        self.copyall(self.req)

        self.req.flush()


class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self, netloc=None):
        tls.db = database.DB()

        try:
            self._handle(netloc)
        except EOFException:
            pass
        except socket.gaierror as e:
            print >>sys.stderr, e
        except IOError as e:
            if e.errno != errno.EPIPE:
                raise
        except ssl.SSLError as e:
            print >>sys.stderr, e

    def _handle(self, netloc=None):
        f = self.request.makefile()

        req = Request(f, netloc)

        if req.verb == "CONNECT" and netloc is None:
            cn = req.netloc()[0]
            with certlock:
                if not os.path.exists("certs/%s.crt" % cn):
                    sslca.make_cert(cn)

            req.write("HTTP/1.1 200 Connection established\r\n\r\n")
            req.flush()

            self.request = ssl.wrap_socket(self.request, server_side=True,
                                           keyfile="certs/%s.key" % cn,
                                           certfile="certs/%s.crt" % cn)

            return self.handle(req.netloc())

        if req.verb == "GET" and req.netloc() == ("rubygems.org", 443) and re.match(r"^/api/v1/dependencies\?", req.path()):
            url = list(req.url)
            qs = urlparse.parse_qs(url[4])
            qs["gems"] = ",".join(sorted(qs["gems"][0].split(",")))
            url[4] = urllib.urlencode(qs)
            req.url = urlparse.ParseResult(*url)

        if req.verb == "GET" and req.netloc() == ("cacert", 80):
            resp = LocalResponse(req, "certs/ca.crt")
        else:
            try:
                resp = CachedResponse(req)

            except NotInCacheException:
                resp = UncachedResponse(req)

        resp.serve()

        f.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(ip="0.0.0.0", port="8080"):
    database.DB().create()
    return ThreadedTCPServer((ip, int(port)), ThreadedTCPRequestHandler)


if __name__ == "__main__":
    server = make_server(*sys.argv[1:])
    print >>sys.stderr, "Listening on %s:%s..." % server.server_address
    server.serve_forever()
