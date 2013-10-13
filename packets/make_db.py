from app import PcapImporter, ImportPcapException
import os, sys

try:
 f=sys.argv[1]
except IndexError:
 print("Usage: %s db_file" % sys.argv[0])
 sys.exit(1)
try:
 imp = PcapImporter(db_file=f)
except ImportPcapException, e:
 print("Error making db: %s" % e)

