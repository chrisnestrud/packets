from flask import Module, render_template, g, abort
pcap=Module(__name__)
@pcap.route('/pcap/<file_hash>/')
def func(file_hash):
 ct = check_queue(file_hash)
 if ct: return ct
 try:
  fn = g.db.execute("select file_name from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
  pcap_id = g.db.execute("select rowid from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
  stats = query_db("select stat, value from stat where pcap_id = ? order by stat", (pcap_id,))
  return render_template("pcap.html", filehash=file_hash, filename=fn, stats=stats)
 except TypeError:
  return render_template("404_pcap.html"), 404

def check_queue(file_hash):
 cur = g.db.execute("select file_name from queue_file where file_hash = ?", (file_hash,)).fetchone()
 if cur:
  fn = cur[0]
  return render_template("pcap_queue.html", filehash=file_hash, filename=fn)

def query_db(query, args=(), one=False):
 cur = g.db.execute(query, args)
 rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
 return (rv[0] if rv else None) if one else rv

