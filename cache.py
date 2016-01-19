#!/usr/bin/python

import database
import errno
import httplib
import os
import re
import rfc822
import socket
import SocketServer
import sslca
import sys
import tempfile
import threading
import urllib
import urlparse
import zlib

if sys.version_info >= (2, 7, 9):
    import ssl
else:
    import backports.ssl as ssl


blacklist = []
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


class UncachedResponse(IO):
    def __init__(self, _req):
        super(UncachedResponse, self).__init__(None)

        self.req = _req

        self.s = socket.socket()

        if self.req.url.scheme == "https":
            if os.environ.get("https_proxy", ""):
                proxy = http_netloc(urlparse.urlparse(os.environ["https_proxy"]))
                self.s.connect(proxy)
                self.f = self.s.makefile()
                self.write("CONNECT %s:%u HTTP/1.1\r\n\r\n" % http_netloc(self.req.url))
                self.flush()
                (http, code, other) = self.readline().split(" ", 2)
                if code != "200":
                    raise Exception()
                headers = rfc822.Message(self.f, False)

            else:
                self.s.connect(http_netloc(self.req.url))

            clientctx = mk_clientctx()
            self.s = clientctx.wrap_socket(self.s, server_hostname=http_netloc(self.req.url)[0])
            self.send_http_req(self.req.path())

        else:
            if os.environ.get("http_proxy", ""):
                proxy = http_netloc(urlparse.urlparse(os.environ["http_proxy"]))
                self.s.connect(proxy)
                self.send_http_req(urlparse.urlunparse(self.req.url))

            else:
                self.s.connect(http_netloc(self.req.url))
                self.send_http_req(self.req.path())

    def send_http_req(self, path):
        self.f = self.s.makefile()

        self.write("%s %s %s\r\n" % (self.req.verb, path, self.req.http))
        self.write(self.req.headers)
        self.write("\r\n")

        if self.req.verb not in ["GET", "HEAD"]:
            self.req.copybody(self)

        self.flush()

    def cacheable(self):
        return self.req.verb == "GET" and \
            "Range" not in self.req.headers and \
            "Content-Range" not in self.headers and \
            http_netloc(self.req.url) != ("auth.docker.io", 443) and \
            self.headers.get("Content-Encoding", "") in ["", "gzip"] and \
            all([rx.match(urlparse.urlunparse(self.req.url)) is None for rx in blacklist])

    def serve(self):
        (self.http, self.code, self.other) = self.readline().split(" ", 2)
        self.code = int(self.code)
        self.headers = rfc822.Message(self.f, False)
        del self.headers["Connection"]
        if int(self.headers.get("Content-Length", 0)) > 0 or self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.headers["Connection"] = "keep-alive"
        else:
            self.headers["Connection"] = "close"

        self.req.write("%s %u %s\r\n" % (self.http, self.code, self.other))
        self.req.write(self.headers)
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

            if self.req.verb != "HEAD":
                self.copybody(self.req)

        self.req.flush()
        self.f.close()
        self.s.close()

        return self.headers["Connection"] == "keep-alive"


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
        self.req.write("Connection: keep-alive\r\n")
        self.req.write("\r\n")
        self.copylength(self.req, self.length)

        self.req.flush()

        return True


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

        return False


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
        while self.__handle(f, netloc):
            pass
        f.close()

    def __handle(self, f, netloc):
        req = Request(f, netloc)

        if req.verb == "CONNECT" and netloc is None:
            cn = http_netloc(req.url)[0]
            with certlock:
                if not os.path.exists("certs/%s.crt" % cn):
                    sslca.make_cert(cn)

            req.write("HTTP/1.1 200 Connection established\r\n\r\n")
            req.flush()

            serverctx = mk_serverctx()
            serverctx.load_cert_chain("certs/%s.crt" % cn, "certs/%s.key" % cn)
            self.request = serverctx.wrap_socket(self.request, server_side=True)

            return self.handle(http_netloc(req.url))

        if req.verb == "GET" and http_netloc(req.url) == ("rubygems.org", 443) and req.path().startswith("/api/v1/dependencies?"):
            url = list(req.url)
            qs = urlparse.parse_qs(url[4])
            qs["gems"] = ",".join(sorted(qs["gems"][0].split(",")))
            url[4] = urllib.urlencode(qs)
            req.url = urlparse.ParseResult(*url)

        if req.verb == "GET" and http_netloc(req.url) == ("cacert", 80):
            resp = LocalResponse(req, "certs/ca.crt")
        else:
            try:
                resp = CachedResponse(req)

            except NotInCacheException:
                resp = UncachedResponse(req)

        return resp.serve()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def http_netloc(url):
    if ":" in url.netloc:
        (host, port) = url.netloc.split(":", 1)
        return (host, int(port))
    elif url.scheme == "http":
        return (url.netloc, 80)
    elif url.scheme == "https":
        return (url.netloc, 443)
    else:
        raise Exception()


def mk_clientctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options |= OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_COMPRESSION
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations("/etc/pki/tls/certs/ca-bundle.crt")
    return ctx


def mk_serverctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options |= OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_COMPRESSION |\
                   OP_CIPHER_SERVER_PREFERENCE | OP_SINGLE_DH_USE |\
                   OP_SINGLE_ECDH_USE
    ctx.set_ciphers("ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:"
                    "DH+AES:ECDH+HIGH:DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:"
                    "RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:!eNULL:!MD5:!DSS:!RC4")
    return ctx


def read_blacklist():
    global blacklist
    blacklist = []

    try:
        with open("blacklist") as f:
            for line in f:
                blacklist.append(re.compile(line.strip()))

    except IOError:
        pass


def make_server(ip="0.0.0.0", port="8080"):
    read_blacklist()
    database.DB().create()
    return ThreadedTCPServer((ip, int(port)), ThreadedTCPRequestHandler)


(OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_COMPRESSION, OP_CIPHER_SERVER_PREFERENCE,
 OP_SINGLE_DH_USE, OP_SINGLE_ECDH_USE) = (16777216, 33554432, 131072, 4194304,
                                          1048576, 524288)

if __name__ == "__main__":
    server = make_server(*sys.argv[1:])
    print >>sys.stderr, "Listening on %s:%s..." % server.server_address
    server.serve_forever()
