#!/usr/bin/python

import errno
import os
import rfc822
import socket
import ssl
import sslca
import sys
import tempfile
import threading
import urlparse
import SocketServer


certlock = threading.Lock()


class EOFException(Exception):
    pass


class NotInCacheException(Exception):
    pass


class IO(object):
    def __init__(self, _f):
        self.f = _f

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

    def copylength(self, dst, n, extra=None):
        while n > 0:
            data = self.read(min(n, 4096))
            if data == "":
                raise EOFException()

            dst.write(data)
            if extra:
                extra.write(data)

            n -= len(data)

    def copychunked(self, dst, extra=None):
        while True:
            n = int(self.readline(), 16)
            dst.write("%x\r\n" % n)

            self.copylength(dst, n, extra)

            if self.read(2) != "\r\n":
                raise EOFException()

            dst.write("\r\n")

            if n == 0:
                break

    def copybody(self, dst, extra=None):
        l = int(self.headers.get("Content-Length", "0"))
        if l:
            self.copylength(dst, l, extra)

        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.copychunked(dst, extra)


class Request(IO):
    def __init__(self, _f, netloc=None):
        self.f = _f

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

    def cache_filename(self):
        return "cache/%s:%u" % self.netloc() + self.path()


class UncachedResponse(IO):
    def __init__(self, _req):
        self.req = _req

        self.s = socket.socket()
        self.s.connect(self.req.netloc())
        if self.req.url.scheme == "https":
            self.s = ssl.wrap_socket(self.s, cert_reqs=ssl.CERT_REQUIRED,
                                     ca_certs="/etc/pki/tls/certs/ca-bundle.crt")
            ssl.match_hostname(self.s.getpeercert(), self.req.netloc()[0])
        self.f = self.s.makefile()

        self.write("%s %s %s\r\n" % (self.req.verb, self.req.path(),
                                     self.req.http))
        self.write(self.req.headers)
        self.write("\r\n")

        self.req.copybody(self)

        self.flush()

    def cacheable(self):
        return self.req.verb == "GET" and self.code == 200 and \
            "Range" not in self.req.headers and \
            "Content-Range" not in self.headers

    def serve(self):
        (self.http, self.code, self.other) = self.readline().split(" ", 2)
        self.code = int(self.code)
        self.headers = rfc822.Message(self.f, False)

        self.req.write("%s %u %s\r\n" % (self.http, self.code, self.other))
        self.req.write(self.headers)
        self.req.write("\r\n")

        if self.cacheable():
            cw = CacheWriter(self.req.cache_filename())
            self.copybody(self.req, cw)
            cw.persist()
        else:
            self.copybody(self.req)

        self.req.flush()
        self.f.close()
        self.s.close()


class CacheWriter(IO):
    def __init__(self, _filename):
        self.filename = _filename
        self.f = tempfile.NamedTemporaryFile(dir="cache")

    def persist(self):
        os.chmod(self.f.name, 0644)

        try:
            os.makedirs(os.path.dirname(self.filename))
        except OSError:
            pass

        try:
            os.link(self.f.name, self.filename)
        except OSError:
            pass

        self.f.close()


class CachedResponse(IO):
    def __init__(self, _req):
        self.req = _req

        if self.req.verb != "GET" or self.req.headers.get("Range"):
            raise NotInCacheException()

        try:
            self.f = open(self.req.cache_filename(), "r")
        except IOError:
            raise NotInCacheException()

    def serve(self):
        self.req.write("HTTP/1.1 200 OK\r\n")

        st = os.fstat(self.f.fileno())
        self.req.write("Content-Length: %u\r\n" % st.st_size)
        self.req.write("Connection: close\r\n")
        self.req.write("\r\n")
        self.copylength(self.req, st.st_size)

        self.req.flush()


class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self, netloc=None):
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

        if req.verb == "GET" and req.netloc() == ("cacert", 80):
            req.cache_filename = lambda: "certs/ca.crt"

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
    return ThreadedTCPServer((ip, int(port)), ThreadedTCPRequestHandler)


try:
    os.mkdir("cache")
except OSError:
    pass

if __name__ == "__main__":
    server = make_server(*sys.argv[1:])
    print >>sys.stderr, "Listening on %s:%s..." % server.server_address
    server.serve_forever()
