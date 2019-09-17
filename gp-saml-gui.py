#!/usr/bin/env python3

import gi
import argparse
import pprint
import urllib
import requests
import xml.etree.ElementTree as ET

from sys import stderr
from binascii import a2b_base64

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

gi.require_version('WebKit2', '4.0')
from gi.repository import WebKit2

class SAMLLoginView:
    def __init__(self, uri, html=None, verbose=False):
        window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0
        # TODO: cookies, see https://stackoverflow.com/questions/48368219/webkit2-webview-how-to-store-cookies-and-reuse-it-again

        self.success = False
        self.wview = WebKit2.WebView()
        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)
        window.resize(500, 500)
        window.add(self.wview)
        window.show_all()
        window.set_title("SAML Login")
        window.connect('delete-event', Gtk.main_quit)
        self.wview.connect('load-changed', self.get_saml_headers)

    def get_saml_headers(self, webview, event):
        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        print("Finished loading %s..." % mr.get_uri(), file=stderr)
        rs = mr.get_response()
        h = rs.get_http_headers()
        if h:
            l = []
            def listify(name, value, t=l):
                if (name.startswith('saml-') or name in ('prelogin-cookie', 'portal-userauthcookie')):
                    t.append((name, value))
            h.foreach(listify)
            self.saml_result = d = dict(l)
            if d:
                print("Got SAML relevant headers, done: %r" % d, file=stderr)
                self.success = True
                Gtk.main_quit()

def parse_args(args = None):
    p = argparse.ArgumentParser()
    p.add_argument('-v','--verbose', default=0, action='count')
    p.add_argument('server', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-p','--portal', dest='portal', action='store_true', help='SAML auth to portal')
    x.add_argument('-g','--gateway', dest='portal', action='store_false', help='SAML auth to gateway (default)')
    g = p.add_argument_group('Client certificate')
    g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    p.add_argument('extra', nargs='*', help='Extra form field(s) to pass to include in the login query string (e.g. "magic-cookie-value=deadbeef01234567")')
    args = p.parse_args(args = None)

    args.extra = dict(x.split('=', 1) for x in args.extra)

    if args.cert and args.key:
        args.cert, args.key = (args.cert, args.key), None
    elif args.cert:
        args.cert = (args.cert, None)
    elif args.key:
        p.error('--key specified without --cert')
    else:
        args.cert = None

    return p, args

if __name__ == "__main__":
    p, args = parse_args()

    s = requests.Session()
    s.headers['User-Agent'] = 'PAN GlobalProtect'
    s.cert = args.cert

    # query prelogin.esp and parse SAML bits
    endpoint = 'https://{}/{}/prelogin.esp'.format(args.server, ('global-protect' if args.portal else 'ssl-vpn'))
    res = s.post(endpoint, verify=args.verify, data=args.extra)
    xml = ET.fromstring(res.content)
    sam = xml.find('saml-auth-method')
    sr = xml.find('saml-request')
    if sam is None or sr is None:
        p.error("This does not appear to be a SAML prelogin response (<saml-auth-method> or <saml-request> tags missing)")
    elif sam.text == 'POST':
        print("Got SAML POST content, opening browser...", file=stderr)
        html, uri = a2b_base64(sr.text).decode(), None
    elif sam.text == 'REDIRECT':
        print("Got SAML REDIRECT to %s, opening browser..." % sr.text, file=stderr)
        uri, html = sr.text, None
    else:
        p.error("Unknown SAML method (%s)" % sam.text)

    # spawn WebKit view to do SAML interactive login
    slv = SAMLLoginView(uri, html, verbose=args.verbose)
    Gtk.main()
    if not slv.success:
        p.error('''Login window closed without producing SAML cookie''')

    # extract response and convert to OpenConnect command-line
    un = slv.saml_result.get('saml-username')
    for cn in ('prelogin-cookie', 'portal-userauthcookie'):
        cv = slv.saml_result.get(cn)
        if cv:
            break
    else:
        cn = None

    if args.verbose:
        print('''\n\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print('''    echo {!r} |\n        openconnect --protocol=gp --user={!r} --usergroup={}:{} --passwd-on-stdin {}\n'''.format(
            cv, un, ('portal' if args.portal else 'gateway'), cn, args.server), file=stderr)

    print("HOST={!r}\nUSER={!r}\nCOOKIE={!r}".format('https://%s/%s:%s' % (args.server, ('portal' if args.portal else 'gateway'), cn), un, cv))
