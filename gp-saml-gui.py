#!/usr/bin/env python3

import gi
import argparse
import pprint
import urllib
import requests
import xml.etree.ElementTree as ET
import ssl

from operator import setitem
from os import path
from shlex import quote
from sys import stderr
from binascii import a2b_base64, b2a_base64
from urllib.parse import urlparse

gi.require_version('Gtk', '3.0')
gi.require_version('WebKit2', '4.0')
from gi.repository import Gtk, WebKit2, GLib

class SAMLLoginView:
    def __init__(self, uri, html=None, verbose=False, cookies=None, verify=True):
        window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        self.closed = False
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
        window.connect('delete-event', self.close)
        self.wview.connect('load-changed', self.get_saml_headers)
        self.wview.connect('resource-load-started', self.log_resources)

        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)

    def close(self, window, event):
        self.closed = True
        Gtk.main_quit()

    def log_resources(self, webview, resource, request):
        if self.verbose > 1:
            print('[REQUEST] %s for resource %s' % (request.get_http_method() or 'Request', resource.get_uri()), file=stderr)
        if self.verbose > 2:
            resource.connect('finished', self.log_resource_details, request)

    def log_resource_details(self, resource, request):
        m = request.get_http_method() or 'Request'
        uri = resource.get_uri()
        rs = resource.get_response()
        h = rs.get_http_headers() if rs else None
        if h:
            ct, cl = h.get_content_type(), h.get_content_length()
            content_type, charset = ct[0], ct.params.get('charset')
            content_details = '%d bytes of %s%s for ' % (cl, content_type, ('; charset='+charset) if charset else '')
        print('[RECEIVE] %sresource %s %s' % (content_details if h else '', m, uri), file=stderr)

    def log_resource_text(self, resource, result, content_type, charset=None, show_headers=None):
        data = resource.get_data_finish(result)
        content_details = '%d bytes of %s%s for ' % (len(data), content_type, ('; charset='+charset) if charset else '')
        print('[DATA   ] %sresource %s' % (content_details, resource.get_uri()), file=stderr)
        if show_headers:
            for h,v in show_headers.items():
                print('%s: %s' % (h, v), file=stderr)
            print(file=stderr)
        if charset or content_type.startswith('text/'):
            print(data.decode(charset or 'utf-8'), file=stderr)

    def get_saml_headers(self, webview, event):
        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        uri = mr.get_uri()
        rs = mr.get_response()
        h = rs.get_http_headers()
        if self.verbose:
            print('[PAGE   ] Finished loading page %s' % uri, file=stderr)
        if not h:
            return

        # convert to normal dict
        d = {}
        h.foreach(lambda k, v: setitem(d, k, v))
        # filter to interesting headers
        fd = {name:v for name, v in d.items() if name.startswith('saml-') or name in ('prelogin-cookie', 'portal-userauthcookie')}
        if fd and self.verbose:
            print("[SAML   ] Got SAML result headers: %r" % fd, file=stderr)
            if self.verbose > 1:
                # display everything we found
                ct = h.get_content_type()
                mr.get_data(None, self.log_resource_text, ct[0], ct.params.get('charset'), d)

        # check if we're done
        self.saml_result.update(fd, server=urlparse(uri).netloc)
        GLib.timeout_add(1000, self.check_done)

    def check_done(self):
        d = self.saml_result
        if 'saml-username' in d and ('prelogin-cookie' in d or 'portal-userauthcookie' in d):
            if args.verbose:
                print("[SAML   ] Got all required SAML headers, done.", file=stderr)
            self.success = True
            Gtk.main_quit()

def parse_args(args = None):
    p = argparse.ArgumentParser()
    p.add_argument('server', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-C', '--cookies', default='~/.gp-saml-gui-cookies',
                   help='Use and store cookies in this file (instead of default %(default)s)')
    x.add_argument('-K', '--no-cookies', dest='cookies', action='store_const', const=None,
                   help="Don't use or store cookies at all")
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
        args.cookies = path.expanduser(args.cookies)

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
        if args.verbose:
            print("Looking for SAML auth tags in response to %s..." % endpoint, file=stderr)
        try:
            res = s.post(endpoint, verify=args.verify, data=args.extra)
        except Exception as ex:
            rootex = ex
            while True:
                if isinstance(rootex, ssl.SSLError):
                    break
                elif not rootex.__cause__ and not rootex.__context__:
                    break
                rootex = rootex.__cause__ or rootex.__context__
            if isinstance(rootex, ssl.CertificateError):
                p.error("SSL certificate error (try --no-verify to ignore): %s" % rootex)
            elif isinstance(rootex, ssl.SSLError):
                p.error("SSL error: %s" % rootex)
            else:
                raise
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
    if slv.closed:
        print("Login window closed by user.", file=stderr)
        p.exit(1)
    if not slv.success:
        p.error('''Login window closed without producing SAML cookies.''')

    # extract response and convert to OpenConnect command-line
    un = slv.saml_result.get('saml-username')
    server = slv.saml_result.get('server', args.server)
    for cn in ('prelogin-cookie', 'portal-userauthcookie'):
        cv = slv.saml_result.get(cn)
        if cv:
            break
    else:
        cn = None

    fullpath = ('/global-protect/getconfig.esp' if args.portal else '/ssl-vpn/login.esp')
    shortpath = ('portal' if args.portal else 'gateway')
    if args.verbose:
        print('''\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print('''    echo {} |\n        openconnect --protocol=gp --user={} --usergroup={}:{} --passwd-on-stdin {}'''.format(
            quote(cv), quote(un), quote(shortpath), quote(cn), quote(server)), file=stderr)

        print('''\nSAML response converted to test-globalprotect-login.py invocation:\n''', file=stderr)
        print('''    test-globalprotect-login.py --user={} -p '' \\\n         https://{}{} {}={}\n'''.format(
            quote(un), quote(server), quote(fullpath), quote(cn), quote(cv)), file=stderr)

    varvals = {
        'GP_HOST': quote('https://%s/%s:%s' % (server, shortpath, cn)),
        'GP_USER': quote(un), 'GP_COOKIE': quote(cv),
    }
    print('\n'.join('%s=%s' % pair for pair in varvals.items()))
