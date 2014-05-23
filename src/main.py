# -*- coding: utf-8 -*-
from lxml import etree
from flask.templating import render_template
from flask import Flask, request
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


def prettify(xml):
    parser = etree.XMLParser(remove_blank_text=True)
    parsed = etree.fromstring(xml, parser)
    return etree.tostring(parsed, pretty_print=True)


@app.route('/enc', methods=['get', 'post'])
def enc():

    if request.method == 'GET':
        return render_template('enc.html')

    key = request.form['key'].strip()
    xml = request.form['xml'].strip()
    encrypted = jbelt.enc(xml, base64.b64decode(key))
    return render_template('dec.html', xml=prettify(encrypted), button_label=u'Зашифровать')


@app.route('/dec', methods=['post'])
def dec():
    key = request.form['key'].strip()
    xml = request.form['xml'].strip()
    decrypted = jbelt.dec(xml, base64.b64decode(key))
    return render_template('enc.html', xml=decrypted)


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
