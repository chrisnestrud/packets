from app import PcapImporter, ImportPcapException
import os, sys
imp = PcapImporter()
conn = imp.conn
cur = conn.execute("select rowid, file_name from queue_file order by rowid").fetchone()
if cur:
 try:
  (rowid, filename) = cur
  print("Importing: %s" % filename)
  imp.pcap_file=filename
  imp.import_pcap()
  imp.print_stats()
 except ImportPcapException, e:
  print("Error importing: %s" % e)
 conn.execute("delete from queue_file where rowid = ?", (rowid,))
 conn.commit()
else:
 print("No items in queue.")

