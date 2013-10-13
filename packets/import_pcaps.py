from app import PcapImporter, ImportPcapException
import os

pcap_dir = "../pcaps/"
pcap_files = os.listdir(pcap_dir)
for pcap_file in pcap_files:
 try:
  f = pcap_dir + pcap_file
  print("Importing: %s" % f)
  imp = PcapImporter(pcap_file=f)
  imp.import_pcap()
  imp.print_stats()
 except ImportPcapException, e:
  print("Error importing: %s" % e)

