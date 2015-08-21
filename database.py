#!/usr/bin/python

import apsw

create_sql = """
CREATE TABLE IF NOT EXISTS cache(
  url TEXT NOT NULL PRIMARY KEY,
  code INTEGER NOT NULL,
  headers TEXT,
  content BLOB
);
"""

class DB(apsw.Connection):
    def __init__(self):
        super(DB, self).__init__("webproxycache.db")
        self.setbusytimeout(1000)

    def create(self):
        c = self.cursor()
        c.execute("PRAGMA auto_vacuum = FULL")
        c.execute(create_sql)

    def persist(self, url, code, headers, f):
        try:
            self._persist(url, code, headers, f)
        except apsw.ConstraintError:
            pass

    def _persist(self, url, code, headers, f):
        f.seek(0, 2)
        n = f.tell()
        f.seek(0)
    
        c = self.cursor()
        c.execute("BEGIN")
        c.execute("INSERT INTO cache(url, code, headers, content) "
                  "VALUES(?, ?, ?, zeroblob(?))",
                  (url, code, headers, n))
    
        blob = self.blobopen("main", "cache", "content",
                             self.last_insert_rowid(), True)
        
        while n > 0:
            data = f.read(min(n, 4096))
            if data == "":
                raise Exception()

            blob.write(data)
            n -= len(data)

        blob.close()
        c.execute("COMMIT")

    def serve(self, url):
        c = self.cursor()
        c.execute("SELECT rowid, code, headers, LENGTH(content) FROM cache "
                  "WHERE url = ?", (url, ))

        try:
            row = c.next()
        except StopIteration:
            return
        
        blob = self.blobopen("main", "cache", "content", row[0], False)
        return (row[1], row[2], blob, row[3])
