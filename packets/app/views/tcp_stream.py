from flask import Module, render_template, g, redirect
tcp_stream=Module(__name__)

def query_db(query, args=(), one=False):
 cur = g.db.execute(query, args)
 rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
 return (rv[0] if rv else None) if one else rv

@tcp_stream.route('/pcap/<file_hash>/tcp_stream/')
def tcp_stream_noid(file_hash):
 # no ID supplied, list streams
 fn = g.db.execute("select file_name from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
 streams = query_db("select rowid as stream_id, saddr, daddr, sport, dport from tcp_stream where file_hash = ? order by saddr, sport, daddr, dport, rowid", (file_hash,))
 return render_template("tcp_streams.html", filehash=file_hash, filename=fn, streams=streams)

@tcp_stream.route('/pcap/<file_hash>/tcp_stream/<stream_id>')
def tcp_stream_id(file_hash, stream_id):
 fn = g.db.execute("select file_name from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
 #packets = query_db("select vw_tcp.* from vw_tcp, tcp_stream, tcp_stream_packet where vw_tcp.tcp_id = tcp_stream_packet.tcp_id and tcp_stream_packet.stream_id = tcp_stream.rowid and tcp_stream.file_hash = ? and tcp_stream.rowid = ?  order by tcp_stream_packet.rowid", (file_hash, stream_id))
 packets = query_db("select distinct vw_tcp.* from tcp_stream_packet inner join tcp_stream on tcp_stream_packet.stream_id = tcp_stream.rowid inner join vw_tcp on tcp_stream_packet.tcp_id = vw_tcp.tcp_id where tcp_stream.file_hash = ? and tcp_stream.rowid = ?  order by tcp_stream_packet.rowid", (file_hash, stream_id))
 return render_template("tcp_stream.html", filehash=file_hash, filename=fn, streamid=stream_id, packets=packets)

