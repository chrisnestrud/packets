from flask import Module, render_template, g
pcaps=Module(__name__)
@pcaps.route('/pcaps/')
def func():
 cur = g.db.execute("select rowid, file_name, file_size, file_hash from pcap")
 pcaps = [dict(pcap_id = row[0], file_name = row[1], file_size=row[2], file_hash = row[3]) for row in cur.fetchall()]
 return render_template("pcaps.html", pcaps=pcaps)

