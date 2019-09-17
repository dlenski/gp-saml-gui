gp-saml-gui
===========

This is a helper script to allow you to interactively login to a GlobalProtect VPN
that uses SAML authentication.

Interactive login is, unfortunately, sometimes a necessary alternative to automated
login via scripts such as
[zdave/openconnect-gp-okta](https://github.com/zdave/openconnect-gp-okta).

How to use
==========

Specify the GlobalProtect server URL (portal or gateway) and optional arguments.

This script will pop up a [GTK WebKit2 WebView](https://webkitgtk.org/) window.
After you succesfully complete the SAML login via web forms, the script will output
`GP_HOST`, `GP_USER`, and `GP_COOKIE` variables in a form that can be used by
[OpenConnect](http://www.infradead.org/openconnect/juniper.html)
(similar to the output of `openconnect --authenticate`):

```sh
$ eval $( gp-saml-gui.py -v vpn.company.com )
Got SAML POST content, opening browser...
Finished loading about:blank...
Finished loading https://company.okta.com/app/panw_globalprotect/deadbeefFOOBARba1234/sso/saml...
Finished loading https://company.okta.com/login/sessionCookieRedirect...
Finished loading https://vpn.qorvo.com/SAML20/SP/ACS...
Got SAML relevant headers, done: {'prelogin-cookie': 'blahblahblah', 'saml-username': 'foo12345@corp.company.com', 'saml-slo': 'no', 'saml-auth-status': '1'}

SAML response converted to OpenConnect command line invocation:

    echo 'blahblahblah' |
        openconnect --protocol=gp --user='foo12345@corp.company.com' --usergroup=prelogin-cookie:gateway --passwd-on-stdin vpn.company.com

$ echo $GP_HOST; echo $GP_USER; echo $GP_COOKIE
https://vpn.company.com/gateway:prelogin-cookie
foo12345@corp.company.com
blahblahblah'

$ echo "$GP_COOKIE" | openconnect --protocol=gp -u "$GP_USER" --passwd-on-stdin "$GP_HOST"
```

TODO
====

* Packaging
* Explain dependencies

License
=======

GPLv3 or newer
