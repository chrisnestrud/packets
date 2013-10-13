from flask import Module, render_template, g, redirect
packet=Module(__name__)
from collections import namedtuple

PacketType=namedtuple('PacketType',('description','id_first','id_prev','id_next', 'row'))
packet_types = {
"tcp": PacketType(
description= "TCP",
id_first = lambda hash: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? order by tcp_id limit 1", (hash,)).fetchone()[0],
id_prev = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? and tcp_id < ? order by tcp_id desc limit 1", (file_hash, packet_id)).fetchone()[0],
id_next = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? and tcp_id > ? order by tcp_id limit 1", (file_hash, packet_id)).fetchone()[0],
row = lambda file_hash, packet_id: query_db( "select * from vw_tcp where pcap_file_hash = ? and tcp_id = ?", (file_hash, packet_id), one=True),
),
"udp": PacketType(
description= "UDP",
id_first=lambda hash: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ?  order by udp_id limit 1", (hash,)).fetchone()[0],
id_prev = lambda file_hash, packet_id: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ? and udp_id < ? order by udp_id desc limit 1", (file_hash, packet_id)).fetchone()[0],
id_next = lambda file_hash, packet_id: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ? and udp_id > ? order by udp_id limit 1", (file_hash, packet_id)).fetchone()[0],
row = lambda file_hash, packet_id: query_db( "select * from vw_udp where pcap_file_hash = ? and udp_id = ?", (file_hash, packet_id), one=True),
),
"tcp_printable": PacketType(
description= "TCP with Printable Data",
id_first=lambda hash: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? and tcp_data_text != \"\" order by tcp_id limit 1", (hash,)).fetchone()[0],
id_prev = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? and tcp_id < ? and tcp_data_text != \"\" order by tcp_id desc limit 1", (file_hash, packet_id)).fetchone()[0],
id_next = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where pcap_file_hash = ? and tcp_id > ? and tcp_data_text != \"\" order by tcp_id limit 1", (file_hash, packet_id)).fetchone()[0],
row = lambda file_hash, packet_id: query_db( "select * from vw_tcp where pcap_file_hash = ? and tcp_id = ?", (file_hash, packet_id), one=True),
),
"udp_printable": PacketType(
description= "UDP with Printable Data",
id_first=lambda hash: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ? and udp_data_text != \"\" order by udp_id limit 1", (hash,)).fetchone()[0],
id_prev = lambda file_hash, packet_id: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ? and udp_id < ? and udp_data_text != \"\" order by udp_id desc limit 1", (file_hash, packet_id)).fetchone()[0],
id_next = lambda file_hash, packet_id: g.db.execute("select udp_id from vw_udp where pcap_file_hash = ? and udp_id > ? and udp_data_text != \"\" order by udp_id limit 1", (file_hash, packet_id)).fetchone()[0],
row = lambda file_hash, packet_id: query_db( "select * from vw_udp where pcap_file_hash = ? and udp_id = ?", (file_hash, packet_id), one=True),
),
"tcp_nostream": PacketType(
description= "TCP packet not in a stream",
id_first=lambda hash: g.db.execute("select tcp_id from vw_tcp where tcp_id not in (select tcp_id from tcp_stream_packet) and pcap_file_hash = ? order by tcp_id limit 1", (hash,)).fetchone()[0],
id_prev = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where tcp_id not in (select tcp_id from tcp_stream_packet) and pcap_file_hash = ? and tcp_id < ? order by tcp_id desc limit 1", (file_hash, packet_id)).fetchone()[0],
id_next = lambda file_hash, packet_id: g.db.execute("select tcp_id from vw_tcp where tcp_id not in (select tcp_id from tcp_stream_packet) and pcap_file_hash = ? and tcp_id > ? order by tcp_id limit 1", (file_hash, packet_id)).fetchone()[0],
row = lambda file_hash, packet_id: query_db( "select * from vw_tcp where tcp_id not in (select tcp_id from tcp_stream_packet) and pcap_file_hash = ? and tcp_id = ?", (file_hash, packet_id), one=True),
),
}

def query_db(query, args=(), one=False):
 cur = g.db.execute(query, args)
 rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
 return (rv[0] if rv else None) if one else rv

@packet.route('/pcap/<file_hash>/packet/<packet_type>/')
def packet_noid(file_hash, packet_type):
 # no ID supplied, select first packet
 first_id = packet_types[packet_type].id_first(file_hash)
 url = "/pcap/%s/packet/%s/%s" % (file_hash, packet_type, first_id)
 return redirect(url)

@packet.route('/pcap/<file_hash>/packet/<packet_type>/<packet_id>')
def packet_id(file_hash, packet_type, packet_id):
 fn = g.db.execute("select file_name from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
 packet_info=[]
 row = packet_types[packet_type].row(file_hash, packet_id)
 try:
  first_id = packet_types[packet_type].id_first(file_hash)
  first_row = packet_types[packet_type].row(file_hash, first_id)
 except NameError:
  pass
 try:
  prev_id = packet_types[packet_type].id_prev(file_hash, packet_id)
  prev_row = packet_types[packet_type].row(file_hash, prev_id)
 except (NameError, TypeError):
  pass
 row['time_since_first'] = row['packet_ts']-first_row['packet_ts']
 try:
  row['time_since_previous'] = row['packet_ts']-prev_row['packet_ts']
 except (NameError, TypeError):
  row['time_since_previous'] = 0
 for k in sorted(row.keys()):
  if type(row[k]) == buffer:
   packet_info.append(dict(name=k + " (hex)", value=str(row[k]).encode('hex')))
  else:
   packet_info.append(dict(name=k, value=row[k]))
 try:
  prev_id = packet_types[packet_type].id_prev(file_hash, packet_id)
 except TypeError:
  prev_id=""
 try:
  next_id = packet_types[packet_type].id_next(file_hash, packet_id)
 except TypeError:
  next_id=""
 return render_template("packet.html", filename=fn, filehash=file_hash, packet_info=packet_info, prev_id=prev_id, next_id=next_id, packet_type=packet_type, packet_type_description=packet_types[packet_type].description)

