#!/usr/bin/env python3

try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.0')
    from gi.repository import Gtk, WebKit2, GLib
except ImportError:
    try:
        import pgi as gi
        gi.require_version('Gtk', '3.0')
        gi.require_version('WebKit2', '4.0')
        from pgi.repository import Gtk, WebKit2, GLib
    except ImportError:
        gi = None
if gi is None:
    raise ImportError("Either gi (PyGObject) or pgi module is required.")

import argparse
import pprint
import urllib
import requests
import xml.etree.ElementTree as ET
import ssl
import tempfile

from operator import setitem
from os import path, dup2, execvp
from shlex import quote
from sys import stderr, platform
from binascii import a2b_base64, b2a_base64
from urllib.parse import urlparse, urlencode

class SAMLLoginView:
    def __init__(self, uri, html=None, verbose=False, cookies=None, verify=True):
        Gtk.init()
        window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        self.closed = False
        self.success = False
        self.saml_result = {}
        self.verbose = verbose

        self.ctx = WebKit2.WebContext.get_default()
        if not verify:
            self.ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        self.cookies = self.ctx.get_cookie_manager()
        if cookies:
            self.cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            self.cookies.set_persistent_storage(cookies, WebKit2.CookiePersistentStorage.TEXT)
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
            if self.verbose:
                print("[SAML   ] Got all required SAML headers, done.", file=stderr)
            self.success = True
            Gtk.main_quit()

def parse_args(args = None):
    pf2clientos = dict(linux='Linux', darwin='Mac', win32='Windows', cygwin='Windows')
    clientos2ocos = dict(Linux='linux-64', Mac='mac-intel', Windows='win')
    default_clientos = pf2clientos.get(platform, 'Windows')

    p = argparse.ArgumentParser()
    p.add_argument('server', help='GlobalProtect server (portal or gateway)')
    p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-C', '--cookies', default='~/.gp-saml-gui-cookies',
                   help='Use and store cookies in this file (instead of default %(default)s)')
    x.add_argument('-K', '--no-cookies', dest='cookies', action='store_const', const=None,
                   help="Don't use or store cookies at all")
    x = p.add_mutually_exclusive_group()
    x.add_argument('-p','--portal', dest='interface', action='store_const', const='portal', default='gateway',
                   help='SAML auth to portal')
    x.add_argument('-g','--gateway', dest='interface', action='store_const', const='gateway',
                   help='SAML auth to gateway (default)')
    g = p.add_argument_group('Client certificate')
    g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    g = p.add_argument_group('Debugging and advanced options')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-v','--verbose', default=1, action='count', help='Increase verbosity of explanatory output to stderr')
    x.add_argument('-q','--quiet', dest='verbose', action='store_const', const=0, help='Reduce verbosity to a minimum')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-x','--external', action='store_true', help='Launch external browser (for debugging)')
    x.add_argument('-P','--pkexec-openconnect', action='store_const', dest='exec', const='pkexec', help='Use PolicyKit to exec openconnect')
    x.add_argument('-S','--sudo-openconnect', action='store_const', dest='exec', const='sudo', help='Use sudo to exec openconnect')
    g.add_argument('-u','--uri', action='store_true', help='Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server')
    g.add_argument('--clientos', choices=set(pf2clientos.values()), default=default_clientos, help="clientos value to send (default is %(default)s)")
    p.add_argument('-f','--field', dest='extra', action='append', default=[],
                   help='Extra form field(s) to pass to include in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")')
    p.add_argument('openconnect_extra', nargs='*', help="Extra arguments to include in output OpenConnect command-line")
    args = p.parse_args(args)

    args.ocos = clientos2ocos[args.clientos]
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

def main(args = None):
    p, args = parse_args(args)

    s = requests.Session()
    s.headers['User-Agent'] = 'PAN GlobalProtect'
    s.cert = args.cert

    if2prelogin = {'portal':'global-protect/prelogin.esp','gateway':'ssl-vpn/prelogin.esp'}
    if2auth = {'portal':'global-protect/getconfig.esp','gateway':'ssl-vpn/login.esp'}

    # query prelogin.esp and parse SAML bits
    if args.uri:
        sam, uri, html = 'URI', args.server, None
    else:
        endpoint = 'https://{}/{}'.format(args.server, if2prelogin[args.interface])
        data = {'tmp':'tmp', 'kerberos-support':'yes', 'ipv6-support':'yes', 'clientVer':4100, 'clientos':args.clientos, **args.extra}
        if args.verbose:
            print("Looking for SAML auth tags in response to %s..." % endpoint, file=stderr)
        try:
            res = s.post(endpoint, verify=args.verify, data=data)
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
        if xml.tag != 'prelogin-response':
            p.error("This does not appear to be a GlobalProtect prelogin response\nCheck in browser: {}?{}".format(endpoint, urlencode(data)))
        sam = xml.find('saml-auth-method')
        sr = xml.find('saml-request')
        if sam is None or sr is None:
            p.error("{} prelogin response does not contain SAML tags (<saml-auth-method> or <saml-request> missing)\n\n"
                    "Things to try:\n"
                    "1) Spoof an officially supported OS (e.g. --clientos=Windows or --clientos=Mac)\n"
                    "2) Check in browser: {}?{}".format(args.interface.title(), endpoint, urlencode(data)))
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

    for cn, ifh in (('prelogin-cookie','gateway'), ('portal-userauthcookie','portal')):
        cv = slv.saml_result.get(cn)
        if cv:
            break
    else:
        cn = ifh = None
        p.error("Didn't get an expected cookie. Something went wrong.")

    openconnect_args = [
        "--protocol=gp",
        "--user="+un,
        "--os="+args.ocos,
        "--usergroup="+args.interface+":"+cn,
        "--passwd-on-stdin",
        server
    ] + args.openconnect_extra

    openconnect_command = '''    echo {} |\n        sudo openconnect {}'''.format(
        quote(cv), " ".join(map(quote, openconnect_args)))

    if args.verbose:
        # Warn about ambiguities
        if server != args.server and not args.uri:
            print('''IMPORTANT: During the SAML auth, you were redirected from {0} to {1}. This probably '''
                  '''means you should specify {1} as the server for final connection, but we're not 100% '''
                  '''sure about this. You should probably try both.\n'''.format(args.server, server), file=stderr)
        if ifh != args.interface and not args.uri:
            print('''IMPORTANT: We started with SAML auth to the {} interface, but received a cookie '''
                  '''that's often associated with the {} interface. You should probably try both.\n'''.format(args.interface, ifh),
                  file=stderr)
        print('''\nSAML response converted to OpenConnect command line invocation:\n''', file=stderr)
        print(openconnect_command, file=stderr)

        print('''\nSAML response converted to test-globalprotect-login.py invocation:\n''', file=stderr)
        print('''    test-globalprotect-login.py --user={} --clientos={} -p '' \\\n         https://{}/{} {}={}\n'''.format(
            quote(un), quote(args.clientos), quote(server), quote(if2auth[args.interface]), quote(cn), quote(cv)), file=stderr)

    if args.exec:
        print('''Launching OpenConnect with {}, equivalent to:\n{}'''.format(args.exec, openconnect_command))
        with tempfile.TemporaryFile('w+') as tf:
            tf.write(cv)
            tf.flush()
            tf.seek(0)
            # redirect stdin from this file, before it is closed by the context manager
            # (it will remain accessible via the open file descriptor)
            dup2(tf.fileno(), 0)
        if args.exec == 'pkexec':
            cmd = ["pkexec", "--user", "root", "openconnect"] + openconnect_args
        elif args.exec == 'sudo':
            cmd = ["sudo", "openconnect"] + openconnect_args
        execvp(cmd[0], cmd)

    else:
        varvals = {
            'HOST': quote('https://%s/%s:%s' % (server, if2auth[args.interface], cn)),
            'USER': quote(un), 'COOKIE': quote(cv), 'OS': quote(args.ocos),
        }
        print('\n'.join('%s=%s' % pair for pair in varvals.items()))

if __name__ == "__main__":
    main()
