gp-saml-gui
===========

This is a helper script to allow you to interactively login to a GlobalProtect VPN
that uses SAML authentication.

Interactive login is, unfortunately, sometimes a necessary alternative to automated
login via scripts such as
[zdave/openconnect-gp-okta](https://github.com/zdave/openconnect-gp-okta).

Installation
============

gp-saml-gui uses GTK, which requires Python 3 bindings.

On Debian / Ubuntu, these are packaged as `python3-gi`, `gir1.2-gtk-3.0`, and
`gir1.2-webkit2-4.0`:

```
$ sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

Then, set up a virtual environment that can access these system packages,
activate it, and install the Python dependencies:

```
$ virtualenv --python=python3 --system-site-packages venv
$ . venv/bin/activate
$ pip install requests
```

How to use
==========

Specify the GlobalProtect server URL (portal or gateway) and optional
arguments, such as `--clientos=Windows` (because many GlobalProtect
servers don't require SAML login, but apparently omit it in their configuration
for OSes other than Windows).

This script will pop up a [GTK WebKit2 WebView](https://webkitgtk.org/) window.
After you succesfully complete the SAML login via web forms, the script will output
`HOST`, `USER`, `COOKIE`, and `OS` variables in a form that can be used by
[OpenConnect](http://www.infradead.org/openconnect/juniper.html)
(similar to the output of `openconnect --authenticate`):

```sh
$ eval $( gp-saml-gui.py --clientos=Windows vpn.company.com )
Got SAML POST content, opening browser...
Finished loading about:blank...
Finished loading https://company.okta.com/app/panw_globalprotect/deadbeefFOOBARba1234/sso/saml...
Finished loading https://company.okta.com/login/sessionCookieRedirect...
Finished loading https://vpn.qorvo.com/SAML20/SP/ACS...
Got SAML relevant headers, done: {'prelogin-cookie': 'blahblahblah', 'saml-username': 'foo12345@corp.company.com', 'saml-slo': 'no', 'saml-auth-status': '1'}

SAML response converted to OpenConnect command line invocation:

    echo 'blahblahblah' |
        openconnect --protocol=gp --user='foo12345@corp.company.com' --os=win --usergroup=prelogin-cookie:gateway --passwd-on-stdin vpn.company.com

$ echo $HOST; echo $USER; echo $COOKIE; echo $OS
https://vpn.company.com/gateway:prelogin-cookie
foo12345@corp.company.com
blahblahblah
win

$ echo "$COOKIE" | openconnect --protocol=gp -u "$USER" --os="$OS" --passwd-on-stdin "$HOST"
```

TODO
====

* Packaging

License
=======

GPLv3 or newer
