from flask import Module, render_template, request, redirect, g
from werkzeug import secure_filename
import os
from app import PcapImporter, ImportPcapException
from hashlib import sha1

upload_dir = "pcaps/"

upload_pcap=Module(__name__)

@upload_pcap.route('/upload/pcap/', methods=['GET','POST'])
def func():
 if request.method == 'POST':
  file=request.files['pcap_file']
  if file:
   file_hash = sha1(file.read()).hexdigest()
   file.seek(0)
   filename=secure_filename(file.filename)
   save_filename = os.path.join(upload_dir, filename)
   exists = g.db.execute("select count(*) from pcap where file_hash = ?", (file_hash,)).fetchone()[0]
   if not exists:
    file.save(save_filename)
    g.db.execute("insert into queue_file (file_name, file_hash) values (?, ?)", (save_filename, file_hash))
    g.db.commit()
   return redirect("/pcap/%s" % file_hash)
  else:
   return render_template("upload_pcap.html", error="No file supplied.")
 else:
  return render_template("upload_pcap.html")

