from flask import Module, render_template, g
tcp_dport=Module(__name__)

@tcp_dport.route('/pcap/<file_hash>/tcp/dport')
def func(file_hash):
 rep =[]
 fn = g.db.execute("select file_name from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
 cur =g.db.execute("select ip_src_text, ip_dst_text, tcp_dport, count(*) as packet_count from vw_tcp where pcap_file_name = ? group by ip_src_text, ip_dst_text, tcp_dport order by packet_count desc ", (fn,))
 [rep.append(row) for row in cur]
 return render_template("tcp_dport.html", filename=fn, filehash=file_hash, rep=rep)

