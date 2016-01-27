#!/usr/bin/python

import apsw

create_sql = """
CREATE TABLE IF NOT EXISTS cache(
  url TEXT NOT NULL PRIMARY KEY,
  code INTEGER NOT NULL,
  headers TEXT NOT NULL,
  contentlen INTEGER NOT NULL,
  content BLOB
);
CREATE TABLE IF NOT EXISTS cache2(
  url TEXT NOT NULL PRIMARY KEY REFERENCES cache(url) ON DELETE CASCADE ON UPDATE CASCADE,
  timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

class DB(apsw.Connection):
    def __init__(self):
        super(DB, self).__init__("webproxycache.db")
        self.setbusyhandler(lambda n: True)
        c = self.cursor()
        c.execute("PRAGMA page_size = 4096")
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA foreign_keys = ON")

    def create(self):
        c = self.cursor()
        c.execute("PRAGMA auto_vacuum = FULL")
        c.execute(create_sql)

    def persist(self, url, code, headers, f):
        f.seek(0, 2)
        n = f.tell()
        f.seek(0)

        c = self.cursor()
        c.execute("BEGIN")
        try:
            if not list(c.execute("SELECT rowid from cache WHERE url = ? "
                                  "AND content IS NOT NULL", (url, ))):
                c.execute("REPLACE INTO cache(url, code, headers, contentlen,"
                          "                   content) "
                          "VALUES(?, ?, ?, ?, zeroblob(?))",
                          (url, code, headers, n, n))
                cache_rowid = self.last_insert_rowid()

                c.execute("INSERT INTO cache2(url) VALUES(?)", (url, ))

                blob = self.blobopen("main", "cache", "content", cache_rowid,
                                     True)

                while n > 0:
                    data = f.read(min(n, 4096))
                    if data == "":
                        raise Exception()

                    blob.write(data)
                    n -= len(data)

                blob.close()

            c.execute("COMMIT")

        except:
            c.execute("ROLLBACK")
            raise

    def persist_null(self, url, code, headers, n):
        c = self.cursor()
        c.execute("BEGIN")
        try:
            if not list(c.execute("SELECT rowid from cache WHERE url = ?",
                                  (url, ))):
                c.execute("INSERT INTO cache(url, code, headers, contentlen) "
                          "VALUES(?, ?, ?, ?)",
                          (url, code, headers, n))
                c.execute("INSERT INTO cache2(url) VALUES(?)", (url, ))

            c.execute("COMMIT")

        except:
            c.execute("ROLLBACK")
            raise

    def serve(self, url):
        c = self.cursor()
        c.execute("SELECT rowid, code, headers, contentlen FROM cache "
                  "WHERE url = ? AND content IS NOT NULL", (url, ))

        try:
            row = c.next()
        except StopIteration:
            return

        c.execute("UPDATE cache2 SET timestamp = DATETIME('NOW') "
                  "WHERE url = ?", (url, ))

        blob = self.blobopen("main", "cache", "content", row[0], False)
        return (row[1], row[2], blob, row[3])


    def serve_null(self, url):
        c = self.cursor()
        c.execute("SELECT rowid, code, headers, contentlen FROM cache "
                  "WHERE url = ?", (url, ))

        try:
            row = c.next()
        except StopIteration:
            return

        c.execute("UPDATE cache2 SET timestamp = DATETIME('NOW') "
                  "WHERE url = ?", (url, ))

        return (row[1], row[2], None, row[3])
