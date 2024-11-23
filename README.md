gp-saml-gui
===========

[![Test Workflow Status](https://github.com/dlenski/gp-saml-gui/workflows/build/badge.svg)](https://github.com/dlenski/gp-saml-gui/actions/workflows/test.yml)

Table of Contents
=================

  * [Introduction](#introduction)
  * [Installation](#installation)
    * [First, non-Python Dependencies](#first-non-python-dependencies)
    * [Second, gp-saml-gui itself](#second-gp-saml-gui-itself)
  * [How to use](#how-to-use)
    * [Extra arguments to OpenConnect](#extra-arguments-to-openconnect)
  * [License](#license)

Introduction
============

This is a helper script to allow you to interactively login to a GlobalProtect VPN
that uses [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)
authentication, so that you can subsequently connect with [OpenConnect](https://www.infradead.org/openconnect).
(The GlobalProtect protocol is supported in OpenConnect v8.0 or newer; v8.06+ is recommended.)

Interactive login is, unfortunately, sometimes a necessary alternative to automated
login via scripts such as
[zdave/openconnect-gp-okta](https://github.com/zdave/openconnect-gp-okta).

This script is known to work with many GlobalProtect VPNs using the major single-sign-on (SSO) providers:

- Okta (sign-in URLs typically `https://<company>.okta.com/login/*`)
- Microsoft (sign-in URLs typically `https://login.microsoftonline.com/*`)

Please search and file [issues](https://github.com/dlenski/gp-saml-gui/issues) if you can report success
or failure with other SSO SAML providers.

Installation
============

First, non-Python Dependencies
------------------------------

gp-saml-gui uses either GTK WebKit or Selenium, which both require Python 3 bindings.

- GTK WebKit

  The default WebView implementation is using GTK WebKit.

  On Debian / Ubuntu, these are packaged as `python3-gi`, `gir1.2-gtk-3.0`, and
`gir1.2-webkit2-4.1` (or `gir1.2-webkit2-4.0` for older distributions).

  ```
  $ sudo apt install python3-gi gir1.2-gtk-3.0 'gir1.2-webkit2-4.*'
  ```

(Note that the older version, WebKit2GTK 4.0, is [no longer
maintained](https://wiki.ubuntu.com/SecurityTeam/FAQ#WebKitGTK); more
details in [#92](https://github.com/dlenski/gp-saml-gui/pull/92).)

  On Fedora the matching libraries are packaged in
  `python3-gobject`, `gtk3-devel`, and `webkit2gtk3-devel`:

  ```
  $ sudo dnf install python3-gobject gtk3-devel webkit2gtk3-devel
  ```

  On CentOS the libraries are packaged in `python36-gobject-base`, `python36-gobject`,
`python36-requests` and `webkitgtk3`

  ```
  $ sudo yum install python36-gobject-base python36-gobject python36-requests webkitgtk3
  ```

  On Arch Linux, the libraries are packaged in `gtk3`, `gobject-introspection`
  and `webkit2gtk`:

  ```
  $ sudo pacman -S gtk3 gobject-introspection webkit2gtk
  ```

- Selenium

  If you want to use [Selenium](https://www.selenium.dev/) instead of
  GTK WebKit, you need to install
  [Selenium for Python](https://pypi.org/project/selenium/) and
  [beautifulsoup4](https://pypi.org/project/beautifulsoup4/).

  Use

  ```
  $ pip3 install selenium beautifulsoup4
  ```

  or

  ```
  $ dnf install python3-selenium python3-beautifulsoup4
  ```

  Additionally you need to install and the corresponding
  [Chrome driver](https://chromedriver.chromium.org/downloads).  
  Please unpack / install / symlink `./chromedriver` to the PATH.

  On some systems, chromedriver can be installed by the package manager

  ```
  $ dnf install chromedriver
  ```

  Alternatively, you can download it Example (for Chrome 106 on 64bit Linux):

  ```
  $ wget https://chromedriver.storage.googleapis.com/106.0.5249.21/chromedriver_linux64.zip
  $ unzip chromedriver_linux64.zip
  # put / symlink it to the PATH
  ```

Second, gp-saml-gui itself
--------------------------

Install gp-saml-gui itself using `pip`:

```
$ pip3 install https://github.com/dlenski/gp-saml-gui/archive/master.zip
...
$ gp-saml-gui
usage: gp-saml-gui [-h] [--no-verify] [-C COOKIES | -K] [-p | -g] [-c CERT]
                   [--key KEY] [-v | -q] [-x | -P | -S] [-u]
                   [--clientos {Windows,Linux,Mac}] [-f EXTRA]
                   [-W {WebKit,Selenium}]
                   server [openconnect_extra [openconnect_extra ...]]
gp-saml-gui: error: the following arguments are required: server, openconnect_extra
```

How to use
==========

Specify the GlobalProtect server URL (portal or gateway) and optional
arguments, such as `--clientos=Windows` (because many GlobalProtect
servers don't require SAML login, but apparently omit it in their configuration
for OSes other than Windows).

This script will pop up a [GTK WebKit2 WebView](https://webkitgtk.org/) window
alongside your terminal window (see this [screenshot](screenshot.png)).
After you successfully complete the SAML login via web forms, the script will output
`HOST`, `USER`, `COOKIE`, and `OS` variables in a form that can be used by
[OpenConnect](http://www.infradead.org/openconnect/juniper.html)
(similar to the output of `openconnect --authenticate`):

```sh
$ eval $( gp-saml-gui --gateway --clientos=Windows vpn.company.com )
Got SAML POST content, opening browser...
Finished loading about:blank...
Finished loading https://company.okta.com/app/panw_globalprotect/deadbeefFOOBARba1234/sso/saml...
Finished loading https://company.okta.com/login/sessionCookieRedirect...
Finished loading https://vpn.qorvo.com/SAML20/SP/ACS...
Got SAML relevant headers, done: {'prelogin-cookie': 'blahblahblah', 'saml-username': 'foo12345@corp.company.com', 'saml-slo': 'no', 'saml-auth-status': '1'}

SAML response converted to OpenConnect command line invocation:

    echo 'blahblahblah' |
        openconnect --protocol=gp --user='foo12345@corp.company.com' --os=win --usergroup=gateway:prelogin-cookie --passwd-on-stdin vpn.company.com

$ echo $HOST; echo $USER; echo $COOKIE; echo $OS
https://vpn.company.com/gateway:prelogin-cookie
foo12345@corp.company.com
blahblahblah
win

$ echo "$COOKIE" | openconnect --protocol=gp -u "$USER" --os="$OS" --passwd-on-stdin "$HOST"
```

If you specify either the `-P`/`--pkexec-openconnect` or `-S`/`--sudo-openconnect` options, the script
will automatically invoke OpenConnect as described, using either [`pkexec` from Polkit](https://www.freedesktop.org/software/polkit/docs/0.106/polkit.8.html)
or [`sudo`](https://www.sudo.ws/), as specified.

# Extra Arguments to OpenConnect

Extra arguments needed for OpenConnect can be specified by adding ` -- ` to the command line, and then
appending these. For example:

```sh
$ gp-saml-gui -P --gateway --clientos=Windows vpn.company.com -- --csd-wrapper=hip-report.sh
…
Launching OpenConnect with pkexec, equivalent to:
    echo blahblahblahlongrandomcookievalue |
        sudo openconnect --protocol=gp --user=foo12345@corp.company.com --os=win --usergroup=gateway:prelogin-cookie --passwd-on-stdin vpn.company.com
<pkexec authentication dialog pops up>
<openconnect runs>
```

License
=======

GPLv3 or newer
