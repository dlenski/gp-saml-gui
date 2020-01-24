#!/usr/bin/env python3

import gi
import argparse
import pprint
import urllib
import requests
import xml.etree.ElementTree as ET
import os

from shlex import quote
from sys import stderr
from binascii import a2b_base64, b2a_base64

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

gi.require_version('WebKit2', '4.0')
from gi.repository import WebKit2

class SAMLLoginView:
    def __init__(self, uri, html=None, verbose=False, cookies=None, verify=True):
        window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        self.success = False
        self.saml_result = {}
        self.verbose = verbose

        self.ctx = WebKit2.WebContext.get_default()
        if not args.verify:
            self.ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        self.cookies = self.ctx.get_cookie_manager()
        if args.cookies:
            self.cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            self.cookies.set_persistent_storage(args.cookies, WebKit2.CookiePersistentStorage.TEXT)
        self.wview = WebKit2.WebView()

        window.resize(500, 500)
        window.add(self.wview)
        window.show_all()
        window.set_title("SAML Login")
        window.connect('delete-event', Gtk.main_quit)
        self.wview.connect('load-changed', self.get_saml_headers)
        self.wview.connect('resource-load-started', self.log_resources)

        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)

    def log_resources(self, webview, resource, request):
        if self.verbose > 1:
            print('%s for resource %s' % (request.get_http_method() or 'Request', resource.get_uri()), file=stderr)

    def get_saml_headers(self, webview, event):
        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        if self.verbose:
            print("Finished loading %s" % mr.get_uri(), file=stderr)
        rs = mr.get_response()
        h = rs.get_http_headers()
        if h:
            l = []
            def listify(name, value, t=l):
                if (name.startswith('saml-') or name in ('prelogin-cookie', 'portal-userauthcookie')):
                    t.append((name, value))
            h.foreach(listify)
            d = dict(l)
            if d and self.verbose:
                print("Got SAML result headers: %r" % d, file=stderr)
            d = self.saml_result
            d.update(dict(l))
            if 'saml-username' in d and ('prelogin-cookie' in d or 'portal-userauthcookie' in d):
                print("Got all required SAML headers, done.", file=stderr)
                self.success = True
                Gtk.main_quit()

def parse_args(args = None):
    p = argparse.ArgumentParser()
    p.add_argument('server', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    p.add_argument('-C', '--no-cookies', dest='cookies', action='store_const', const=None,
                   default='~/.gp-saml-gui-cookies', help="Don't use cookies (stored in %(default)s)")
    x = p.add_mutually_exclusive_group()
    x.add_argument('-p','--portal', dest='portal', action='store_true', help='SAML auth to portal')
    x.add_argument('-g','--gateway', dest='portal', action='store_false', help='SAML auth to gateway (default)')
    g = p.add_argument_group('Client certificate')
    g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    g = p.add_argument_group('Debugging and advanced options')
    g.add_argument('-v','--verbose', default=0, action='count')
    g.add_argument('-x','--external', action='store_true', help='Launch external browser (for debugging)')
    g.add_argument('-u','--uri', action='store_true', help='Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server')
    p.add_argument('extra', nargs='*', help='Extra form field(s) to pass to include in the login query string (e.g. "magic-cookie-value=deadbeef01234567")')
    args = p.parse_args(args = None)

    args.extra = dict(x.split('=', 1) for x in args.extra)

    if args.cookies:
        args.cookies = os.path.expanduser(args.cookies)

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
    if args.uri:
        sam, uri, html = 'URI', args.server, None
    else:
        endpoint = 'https://{}/{}/prelogin.esp'.format(args.server, ('global-protect' if args.portal else 'ssl-vpn'))
        res = s.post(endpoint, verify=args.verify, data=args.extra)
        xml = ET.fromstring(res.content)
        sam = xml.find('saml-auth-method')
        sr = xml.find('saml-request')
        if sam is None or sr is None:
            p.error("This does not appear to be a SAML prelogin response (<saml-auth-method> or <saml-request> tags missing)")
        sam = sam.text
        sr = a2b_base64(sr.text).decode()
        if sam == 'POST':
            html, uri = sr, None
        elif sam == 'REDIRECT':
            uri, html = sr, None
        else:
            p.error("Unknown SAML method (%s)" % sam)

    # launch external browser for debugging
    if args.external:
        print("Got SAML %s, opening external browser for debugging..." % sam, file=stderr)
        import webbrowser
        if html:
            uri = 'data:text/html;base64,' + b2a_base64(html.encode()).decode()
        webbrowser.open(uri)
        raise SystemExit

    # spawn WebKit view to do SAML interactive login
    if args.verbose:
        print("Got SAML %s, opening browser..." % sam, file=stderr)
    slv = SAMLLoginView(uri, html, verbose=args.verbose, cookies=args.cookies, verify=args.verify)
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

    fullpath = ('/global-protect/getconfig.esp' if args.portal else '/ssl-vpn/login.esp')
    shortpath = ('portal' if args.portal else 'gateway')
    if args.verbose:
        print('''\n\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print('''    echo {} |\n        openconnect --protocol=gp --user={} --usergroup={}:{} --passwd-on-stdin {}\n'''.format(
            quote(cv), quote(un), quote(shortpath), quote(cn), quote(args.server)), file=stderr)

    varvals = {
        'HOST': quote('https://%s/%s:%s' % (args.server, shortpath, cn)),
        'USER': quote(un), 'COOKIE': quote(cv),
    }
    print('\n'.join('%s=%s' % pair for pair in varvals.items()))
