from pcap_importer import PcapImporter, ImportPcapException
from flask import Flask, g
import sqlite3

app=Flask(__name__)
app.debug=True

@app.before_request
def before_request():
 db_file = 'packets.db'
 g.db = sqlite3.connect(db_file)

@app.after_request
def after_request(response):
 g.db.close()
 return response

from app.views.index import index
app.register_module(index)
from app.views.packet import packet
app.register_module(packet)
from app.views.pcap import pcap
app.register_module(pcap)
from app.views.pcaps import pcaps
app.register_module(pcaps)
from app.views.tcp_dport import tcp_dport
app.register_module(tcp_dport)
from app.views.tcp_stream import tcp_stream
app.register_module(tcp_stream)
from app.views.udp_dport import udp_dport
app.register_module(udp_dport)
from app.views.upload_pcap import upload_pcap
app.register_module(upload_pcap)
