# -*- coding: utf-8 -*-
from flask.templating import render_template
import os
from flask import Flask, request#, url_for
from string import Template
import jbelt
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = set(['xml'])


@app.route('/genkeys', methods=['get', 'post'])
def genkeys():
    length = request.form['length'] if request.method == 'POST' else 128

    keys = jbelt.genKeys(int(length))

    keys['priv'] = base64.b64encode(str(keys['priv']))
    keys['pub'] = base64.b64encode(str(keys['pub']))
    return render_template('keys.html', **keys)


@app.route('/sign', methods=['get', 'post'])
def sign():
    if request.method == 'POST':

        key = request.form['key'].strip()

        if 'upload' in request.query_string:
            file = request.files['file']
            return render_template('sign.html', xml=file.read(), signed='', key=key, is_valid=True)

        key = request.form['key'].strip()
        xml = request.form['xml'].strip()
        signed = request.form['signed'].strip()
        is_valid = False
        if 'verify' in request.query_string:
            is_valid = jbelt.verify(signed)

        elif key and xml:
            signed = jbelt.sign(xml, keys=jbelt.calc_keys(base64.b64decode(key)))
            is_valid = jbelt.verify(signed)
        return render_template('sign.html', xml=xml, signed=signed, key=key, is_valid=is_valid)
    else:
        return render_template('sign.html', xml='', signed='', key=base64.b64encode(str(jbelt.genKeys()['priv'])))


@app.route('/')
def index():
    return render_template('index.html', name='Belt XmlDsig Support')

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
