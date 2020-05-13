#!/usr/bin/python3

from __future__ import print_function
from sys import stderr, version_info, platform
if (version_info >= (3, 0)):
    from urllib.parse import urlparse, urlencode
    raw_input = input
else:
    from urlparse import urlparse
    from urllib import urlencode
import requests
import argparse
import getpass
import os
import xml.etree.ElementTree as ET
import posixpath
from binascii import a2b_base64
from tempfile import NamedTemporaryFile
from shlex import quote
from itertools import chain

clientos_map = dict(linux='Linux', darwin='Mac', win32='Windows', cygwin='Windows')
default_clientos = clientos_map.get(platform, 'Windows')

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('endpoint', help='GlobalProtect server; can append /ssl-vpn/login.esp (default) or /global-protect/getconfig.esp or /{ssl-vpn,global-protect}/prelogin.esp')
p.add_argument('extra', nargs='*', help='Extra field to pass to include in the login query string (e.g. "portal-userauthcookie=deadbeef01234567")')
g = p.add_argument_group('Login credentials')
g.add_argument('-u','--user', help='Username (will prompt if unspecified)')
g.add_argument('-p','--password', help='Password (will prompt if unspecified)')
g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--computer', default=os.uname()[1], help="Computer name (default is `hostname`)")
g.add_argument('--clientos', choices=set(clientos_map.values()), default=default_clientos, help="clientos value to send (default is %(default)s)")
g.add_argument('-k','--key', help='PEM file containing client private key (if not included in same file as certificate)')
p.add_argument('-b','--browse', action='store_true', help='Automatically spawn browser for SAML')
p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

extra = dict(x.split('=', 1) for x in args.extra)
endpoint = urlparse(('https://' if '//' not in args.endpoint else '') + args.endpoint, 'https:')
if not endpoint.path:
    print("Endpoint path unspecified: defaulting to /ssl-vpn/login.esp", file=stderr)
    endpoint = endpoint._replace(path = '/ssl-vpn/login.esp')
prelogin = (posixpath.split(endpoint.path)[-1] == 'prelogin.esp')

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert, None)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'
s.cert = cert

if prelogin:
    data={
        # sent by many clients but not known to have any effect
        'tmp': 'tmp', 'clientVer': 4100, 'kerberos-support': 'yes', 'ipv6-support': 'yes',
        # affects some clients' behavior (https://github.com/dlenski/gp-saml-gui/issues/6#issuecomment-599743060)
        'clientos': args.clientos,
        **extra
    }
else:
    # same request params work for /global-protect/getconfig.esp as for /ssl-vpn/login.esp
    if args.user == None:
        args.user = raw_input('Username: ')
    if args.password == None:
        args.password = getpass.getpass('Password: ')
    data=dict(user=args.user, passwd=args.password,
              # required
              jnlpReady='jnlpReady', ok='Login', direct='yes',
              # optional but might affect behavior
              clientVer=4100, server=endpoint.netloc, prot='https:',
              computer=args.computer,
              **extra)
res = s.post(endpoint.geturl(), verify=args.verify, data=data)

if args.verbose:
    print("Request body:\n", res.request.body, file=stderr)

res.raise_for_status()

# build openconnect "cookie" if the result is a <jnlp>

try:
    xml = ET.fromstring(res.text)
except Exception:
    xml = None

if cert:
    cert_and_key = '\\\n        ' + ' '.join('%s "%s"' % (opt, quote(fn)) for opt, fn in zip(('-c','-k'), cert) if fn) + ' \\\n'
else:
    cert_and_key = ''

if xml is not None and xml.tag == 'jnlp':
    arguments = [(t.text or '') for t in xml.iter('argument')]
    arguments += [''] * (16-len(arguments))
    cookie = urlencode({'authcookie': arguments[1], 'portal': arguments[3], 'user': arguments[4], 'domain': arguments[7],
                        'computer': args.computer, 'preferred-ip': arguments[15]})

    print('''

Extracted connection cookie from <jnlp>. Use this to connect:

    openconnect --protocol=gp --usergroup=gateway %s \\
        --cookie %s%s
''' % (quote(endpoint.netloc), quote(cookie), cert_and_key), file=stderr)

# do SAML request if the result is <prelogin-response><saml...>

elif xml is not None and xml.tag == 'prelogin-response' and None not in (xml.find('saml-auth-method'), xml.find('saml-request')):
    import webbrowser
    sam = xml.find('saml-auth-method').text
    sr = a2b_base64(xml.find('saml-request').text)
    if sam == 'POST':
        with NamedTemporaryFile(delete=False, suffix='.html') as tf:
            tf.write(sr)
        if args.browse:
            print("Got SAML POST, browsing to %s" % tf.name)
            webbrowser.open('file://' + tf.name)
        else:
            print("Got SAML POST, saved to:\n\t%s" % tf.name)
    elif sam == 'REDIRECT':
        sr = a2b_base64(sr)
        if args.browse:
            print("Got SAML REDIRECT, browsing to %s" % sr)
            webbrowser.open(sr)
        else:
            print("Got SAML REDIRECT to:\n\t%s" % sr)

# if it's a portal config response, pass along to gateway

elif xml is not None and xml.tag == 'policy':

    uemail = xml.find('user-email')
    if uemail: uemail = uemail.text
    cookies = [(cn, xml.find(cn).text) for cn in ('portal-prelogonuserauthcookie', 'portal-userauthcookie')]
    gateways = [(e.find('description').text, e.get('name')) for e in set(chain(xml.findall('gateways/external/list/entry'), xml.findall('gateways6/external/list/entry')))]

    print('''\nPortal config response response converted to new test-globalprotect-login.py invocation for gateway login:\n'''
          '''    test-globalprotect-login.py --user={} --clientos={} -p {} {}\\\n'''
          '''        https://{}/ssl-vpn/login.esp \\\n'''
          '''        {}\n'''.format(
              quote(args.user), quote(args.clientos), quote(args.password), cert_and_key, quote(gateways[0][1]),
              ' '.join(cn+'='+quote(cv) for cn, cv in cookies),
              file=stderr))

    if uemail and uemail != args.user:
        print('''IMPORTANT: Portal config contained different username. You might need to try\n'''
              '''{} instead.\n'''.format(uemail))
    if len(gateways)>1:
        print('''Received multiple gateways. Options include:\n    {}\n'''.format('\n    '.join('%s => %s' % (desc, host) for desc, host in gateways)))

# Just print the result

else:
    if args.verbose:
        print(res.headers, file=stderr)
    print(res.text)
