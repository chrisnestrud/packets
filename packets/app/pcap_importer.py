import dpkt
import os
import sys
import sqlite3
from hashlib import sha1
from os.path import getsize
import socket
from dpkt.ip import IP
from collections import namedtuple
import time

class ImportPcapException(Exception): pass
class AlreadyImportedException(ImportPcapException): pass

PacketInfo = namedtuple('PacketInfo', ('dst', 'hl', 'id', 'len', 'off', 'opts', 'src', 'sum', 'tos', 'ttl'))

class PcapImporter(object):
 def __init__(self, pcap_file=None, file_hash=None, db_file="packets.db", stats={}, sg={}, tcp_packets={}, streams={}, do_update_ipaddrs=True, do_update_tcp_streams=True):
  self.pcap_file=pcap_file
  self.file_hash=file_hash
  self.db_file=db_file
  self.sg=sg
  self.streams=streams
  self.tcp_packets=tcp_packets
  self.stats=stats
  self.stats.clear()
  self.do_update_ipaddrs=do_update_ipaddrs
  self.do_update_tcp_streams=do_update_tcp_streams
  self.conn = sqlite3.connect(db_file)
  self.conn.text_factory=str
  self.setup_db()

 def setup_db(self):
  conn=self.conn
  sql = (
"create table queue_file (file_name text, file_hash text)",
"create table pcap (file_name text, file_size integer, file_hash text, snaplen integer)",
"create table packet (pcap_id integer, ts float, data buffer, data_len integer)",
"create table ethernet (packet_id integer, src buffer, dst buffer, type integer)",
"create table ip (ethernet_id integer, dst buffer, hl, id, len, off, opts, src buffer, sum, tos, ttl)",
"create table stat (pcap_id integer, stat text, value text)",
"create table tcp (ip_id integer, ack buffer, data buffer, data_len integer, data_text text, dport buffer, flags buffer, off buffer, off_x2 buffer, opts buffer, seq buffer, sport buffer, sum buffer, urp buffer, win buffer)",
"create table tcp_stream (file_hash, saddr, daddr, sport, dport)",
"create table tcp_stream_packet (stream_id integer, tcp_id integer)",
"create table udp (ip_id integer, data buffer, data_len integer, data_text text, dport buffer, sport buffer, sum buffer, ulen integer)",
"create table arp (ethernet_id integer, hln buffer, hrd buffer, op buffer, pln buffer, pro buffer, sha buffer, spa buffer, tha buffer, tpa buffer)",
"create table ip_addr (n buffer, a text)",
"create view vw_tcp as select distinct tcp.rowid as tcp_id, tcp.ack as tcp_ack, tcp.data as tcp_data, tcp.data_len as tcp_data_len, tcp.data_text as tcp_data_text, tcp.dport as tcp_dport, tcp.flags as tcp_flags, tcp.seq as tcp_seq, tcp.sport as tcp_sport, tcp.sum as tcp_sum, tcp.urp as tcp_urp, tcp.win as tcp_win, ip.dst as ip_dst, ip.src as ip_src, ip.ttl as ip_ttl, ethernet.src as ethernet_src, ethernet.dst as ethernet_dst, packet.ts as packet_ts, a1.a as ip_src_text, a2.a as ip_dst_text, pcap.file_hash as pcap_file_hash, pcap.file_name as pcap_file_name from tcp, ip, ethernet, packet, pcap, ip_addr as a1, ip_addr as a2 where a1.n = ip.src and a2.n = ip.dst and tcp.ip_id = ip.rowid and ip.ethernet_id = ethernet.rowid and ethernet.packet_id = packet.rowid and packet.pcap_id = pcap.rowid",
"create view vw_tcp_nostream as select * from vw_tcp where tcp_id not in (select tcp_id from tcp_stream_packet)",
"create view vw_udp as select distinct udp.rowid as udp_id, udp.data as udp_data, udp.data_len as udp_data_len, udp.data_text as udp_data_text, udp.dport as udp_dport, udp.sport as udp_sport, ip.dst as ip_dst, ip.src as ip_src, ip.ttl as ip_ttl, ethernet.src as ethernet_src, ethernet.dst as ethernet_dst, packet.ts as packet_ts, pcap.file_hash as pcap_file_hash, pcap.file_name as pcap_file_name, a1.a as ip_src_text, a2.a as ip_dst_text from udp, ip, ethernet, packet, pcap, ip_addr as a1, ip_addr as a2 where a1.n = ip.src and a2.n = ip.dst and udp.ip_id = ip.rowid and ip.ethernet_id = ethernet.rowid and ethernet.packet_id = packet.rowid and packet.pcap_id = pcap.rowid",
)
  if not conn.execute('select count(*) from sqlite_master').fetchone()[0]:
   [conn.execute(s) for s in sql]
   conn.commit()

 def import_pcap(self):
  t1=time.time()
  pcap_file=self.pcap_file
  conn=self.conn
  if not self.file_hash: self.file_hash = sha1(open(self.pcap_file, 'rb').read()).hexdigest()
  hash =self.file_hash
  size=os.path.getsize(pcap_file)
  if conn.execute("select count(*) from pcap where file_hash = ?", (hash,)).fetchone()[0]:
   raise AlreadyImportedException("File %s already exists with ash %s" % (pcap_file, hash))
  r=dpkt.pcap.Reader(open(pcap_file, 'rb'))
  pcap_id = conn.execute("insert into pcap (file_name, file_size, file_hash, snaplen) values (?, ?, ?, ?)", (pcap_file, size, hash, r.snaplen)).lastrowid
  [self.add_packet(pcap_id, ts, data) for ts, data in r]
  if self.do_update_ipaddrs: self.update_ipaddrs()
  if self.do_update_tcp_streams: self.update_tcp_streams()
  self.conn.commit()
  t2=time.time()
  self.set_stat("time_import_start", t1)
  self.set_stat("time_import_end", t2)
  self.set_stat("time_import_elapsed", t2-t1)
  self.update_stats()

 def add_packet(self, pcap_id, ts, data):
  conn=self.conn
  packet_id = conn.execute("insert into packet (pcap_id, ts, data, data_len) values (?, ?, ?, ?)", (pcap_id, ts, buffer(data), len(data))).lastrowid
  self.increase_stat("add_packet_packet", 1)
  eth = dpkt.ethernet.Ethernet(data)
  ethernet_id = conn.execute("insert into ethernet (packet_id, src, dst, type) values (?, ?, ?, ?)", (packet_id, buffer(eth.src), buffer(eth.dst), eth.type)).lastrowid
  self.increase_stat("add_packet_eth", 1)
  if eth.type == dpkt.ethernet.ETH_TYPE_IP:
   ip=eth.data
   ip_id = conn.execute("insert into ip (ethernet_id, dst, hl, id, len, off, opts, src, sum, tos, ttl) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (ethernet_id, buffer(ip.dst), ip.hl, ip.id, ip.len, ip.off, ip.opts, buffer(ip.src), ip.sum, ip.tos, ip.ttl)).lastrowid
   self.increase_stat("add_packet_ip", 1)
   if ip.p == dpkt.ip.IP_PROTO_TCP:
    tcp = ip.data
    tcp_data = ""
    for char in tcp.data:
     if  ord(char) in range(1,128):
      tcp_data+=char
    tcp_id = conn.execute("insert into tcp (ip_id, ack, data, data_len, data_text, dport, flags, off, off_x2, opts, seq, sport, sum, urp, win) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (ip_id, tcp.ack, buffer(tcp.data), len(tcp.data), tcp_data, tcp.dport, tcp.flags, tcp.off, tcp.off_x2, tcp.opts, tcp.seq, tcp.sport, tcp.sum, tcp.urp, tcp.win)).lastrowid
    self.increase_stat("add_packet_tcp", 1)
   elif ip.p == dpkt.ip.IP_PROTO_UDP:
    udp = ip.data
    udp_data = ""
    for char in udp.data:
     if  ord(char) in range(1,128):
      udp_data+=char
    udp_id = conn.execute("insert into udp (ip_id, data, data_len, data_text, dport, sport, sum, ulen) values (?, ?, ?, ?, ?, ?, ?, ?)", (ip_id, buffer(udp.data), len(udp.data), udp_data, udp.dport, udp.sport, udp.sum, udp.ulen)).lastrowid
    self.increase_stat("add_packet_udp", 1)
  elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
   arp = eth.data
   arp_id = conn.execute("insert into arp (ethernet_id, hln, hrd, op, pln, pro, sha, spa, tha, tpa) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (ethernet_id, arp.hln, arp.hrd, arp.op, arp.pln, arp.pro, arp.sha, arp.spa, arp.tha, arp.tpa)).lastrowid
   self.increase_stat("add_packet_arp", 1)

 def update_ipaddrs(self):
  t1=time.time()
  conn=self.conn
  c=conn.cursor()
  c.execute("select src from ip union select dst from ip")
  for row in c:
   n = row[0]
   a = socket.inet_ntoa(n)
   conn.execute("insert into ip_addr (n, a) values (?, ?)", (n, a))
   self.increase_stat("update_ipaddrs_ips", 1)
  t2=time.time()
  self.set_stat("time_updateipaddrs_start", t1)
  self.set_stat("time_updateipaddrs_end", t2)
  self.set_stat("time_updateipaddrs_elapsed", t2-t1)

 def update_tcp_streams(self):
  t1=time.time()
  conn=self.conn
  filename=self.pcap_file
  file_hash=self.file_hash
  self.sg['conn']=conn
  self.sg['file_hash'] = file_hash
  # cache all the tcp packets
  packets = self.query_db("select tcp.rowid, ip.dst, ip.hl, ip.id, ip.len, ip.off, ip.opts, ip.src, ip.sum, ip.tos, ip.ttl from tcp inner join ip on tcp.ip_id = ip.rowid")
  for p in packets:
   pi = PacketInfo(str(p['dst']), str(p['hl']), str(p['id']), str(p['len']), str(p['off']), str(p['opts']), str(p['src']), str(p['sum']), str(p['tos']), str(p['ttl']))
   self.tcp_packets[pi] = p['rowid']
  import nids
  self.nids=nids
  self.nids.param("n_tcp_streams", 400000)
  self.nids.param("scan_num_hosts", 0)  # disable portscan detection
  self.nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
  self.nids.param("filename", filename)
  try:
   self.nids.init()
  except self.nids.error, e:
   print "initialization error", e
  self.nids.register_ip(self.handle_ip)
  self.nids.register_tcp(self.handle_tcp)
  #self.nids.register_udp(self.handle_udp)
  #self.nids.register_ip_frag(self.handle_ip_frag)
  self.nids.run()
  t2=time.time()
  self.set_stat("time_updatetcpstreams_start", t1)
  self.set_stat("time_updatetcpstreams_end", t2)
  self.set_stat("time_updatetcpstreams_elapsed", t2-t1)

 def handle_ip(self, ip):
  pkt=IP(ip)
  self.sg['pkt']=pkt
  self.increase_stat("handle_ip_packets", 1)
 
 def handle_tcp(self, tcp):
  self.increase_stat("handle_tcp", 1)
  end_states = (self.nids.NIDS_CLOSE, self.nids.NIDS_RESET, self.nids.NIDS_TIMEOUT)
  #print("tcp addr is ", tcp.addr)
  if tcp.nids_state == self.nids.NIDS_JUST_EST:
   tcp.client.collect = 1
   tcp.server.collect = 1
   self.streams[tcp.addr] = self.new_stream_id(conn=self.sg['conn'], addr=tcp.addr, file_hash=self.sg['file_hash'])
   self.increase_stat("handle_tcp_est", 1)
   #print("Just established, set %s to stream ID %s" % (tcp.addr, self.streams[tcp.addr]))
  elif tcp.addr not in self.streams:
   tcp.client.collect = 1
   tcp.server.collect = 1
   self.streams[tcp.addr] = self.new_stream_id(conn=self.sg['conn'], addr=tcp.addr, file_hash=self.sg['file_hash'])
   self.increase_stat("handle_tcp_middle", 1)
   #print("Picked up in middle, set %s to stream ID %s" % (tcp.addr, self.streams[tcp.addr]))
  if tcp.nids_state == self.nids.NIDS_DATA:
   tcp.discard(0)
  # add the packet
  stream_id = self.streams[tcp.addr]
  tcp_id = self.get_tcp_id(self.sg['conn'], self.sg['pkt'])
  #print("Adding TCP packet %s to TCP stream %s" % (tcp_id, stream_id))
  try:
   self.add_stream_packet(self.sg['conn'], stream_id, tcp_id)
  except KeyError:
   pass
  if tcp.nids_state in end_states:
   #print("End state, deleting %s with stream ID %s" % (tcp.addr, self.streams[tcp.addr]))
   del(self.streams[tcp.addr])
   self.increase_stat("handle_tcp_end", 1)

 def handle_udp(self, addr, pkt, payload):
  self.increase_stat("handle_udp", 1)

 def handle_ip_frag(self, *args):
  self.increase_stat("handle_ip_frag", 1)

 def new_stream_id(self, conn=None, addr=None, file_hash=None):
  stream_id = conn.execute("insert into tcp_stream (file_hash, saddr, daddr, sport, dport) values (?, ?, ?, ?, ?)", (file_hash, addr[0][0], addr[1][0], addr[0][1], addr[1][1])).lastrowid
  self.increase_stat("new_stream_id", 1)
  return stream_id

 def get_tcp_id(self, conn=None, ip_pkt=None):
  pi = PacketInfo(str(ip_pkt['dst']), str(ip_pkt['hl']), str(ip_pkt['id']), str(ip_pkt['len']), str(ip_pkt['off']), str(ip_pkt['opts']), str(ip_pkt['src']), str(ip_pkt['sum']), str(ip_pkt['tos']), str(ip_pkt['ttl']))
  self.increase_stat("get_tcp_id", 1)
  try:
   tcp_id = self.tcp_packets[pi]
  except KeyError:
   #print("Can't find TCP ID")
   return 0
  return tcp_id

 def add_stream_packet(self, conn=None, stream_id=None, tcp_id=None):
  self.increase_stat("add_stream_packet", 1)
  conn.execute("insert into tcp_stream_packet (stream_id, tcp_id) values (?, ?)", (stream_id, tcp_id))

 def query_db(self, query, args=(), one=False):
  cur = self.conn.execute(query, args)
  rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
  return (rv[0] if rv else None) if one else rv

 def increase_stat(self, stat, inc):
   try: self.stats[stat]+=inc
   except KeyError: self.stats[stat]=inc

 def set_stat(self, stat, val):
  self.stats[stat]=val

 def print_stats(self):
  print("Stats for %s:" % self.pcap_file)
  for key in sorted(self.stats.keys()):
   print("%s: %s" % (key, self.stats[key]))

 def update_stats(self):
  pcap_id = self.conn.execute("select rowid from pcap where file_hash = ?", (self.file_hash,)).fetchone()[0]
  for key in self.stats.keys():
   self.conn.execute("insert into stat (pcap_id, stat, value) values (?, ?, ?)", (pcap_id, key, self.stats[key]))
  self.conn.commit()

