from app import PcapImporter, ImportPcapException
import os, sys

try:
 f=sys.argv[1]
except IndexError:
 print("Usage: %s pcap_file" % sys.argv[0])
 sys.exit(1)
try:
 print("Importing: %s" % f)
 imp = PcapImporter(pcap_file=f)
 imp.import_pcap()
 imp.print_stats()
except ImportPcapException, e:
 print("Error importing: %s" % e)

