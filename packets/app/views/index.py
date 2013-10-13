from flask import Module, render_template
index=Module(__name__)
@index.route('/')
def func():
 return render_template("index.html")

