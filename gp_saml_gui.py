#!/usr/bin/env python3

import argparse
import dataclasses
import gi
import logging
import operator
import requests
import ssl
import sys
import tempfile
import urllib3

import xml.etree.ElementTree as ET

from os import path, dup2, execvp, environ
from shlex import quote
from binascii import a2b_base64, b2a_base64
from urllib.parse import urlparse, urlencode
from html.parser import HTMLParser

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")

from gi.repository import Gtk, WebKit2, GLib  # noqa: E402  # type: ignore

_SAML_COOKIE_NAME = {
    "prelogin-cookie": "gateway",
    "portal-userauthcookie": "portal",
}

_SAML_PRELOGIN_PATH = {
    "gateway": "ssl-vpn/prelogin.esp",
    "portal": "global-protect/prelogin.esp",
}

_SAML_AUTH_PATH = {
    "gateway": "ssl-vpn/login.esp",
    "portal": "global-protect/getconfig.esp",
}

_VERBOSITY_TO_LOGGING_LEVEL = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}

_PYTHON_PLATFORM_TO_CLIENT_OS = {
    "linux": "Linux",
    "darwin": "Mac",
    "win32": "Windows",
    "cygwin": "Windows",
}

_CLIENT_OS_TO_OPENCONNECT_OS = {
    "Linux": "linux-64",
    "Mac": "mac-intel",
    "Windows": "win",
}

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class GPConnectionInfo:
    "Data class to hold the Global Protect connection info"

    uri: str
    insecure: bool
    user_agent: str
    cert: str
    key: str
    verify: bool
    interface: str
    server: str
    clientos: str
    prelogin_extra_fields: dict
    cookiejar: str
    no_proxy: bool
    retry: int

    @property
    def defined_user_agent(self):
        "Provide a valid user agent"
        return "PAN GlobalProtect" if self.user_agent is None else self.user_agent

    @property
    def certkey(self):
        "Get the certificate and key from the connection info"
        if self.cert is None and self.key is None:
            return None
        return self.cert, self.key


@dataclasses.dataclass
class LoginRequestInfo:
    "Data class to hold the SAML login request info"

    method: str  # saml-auth-method
    uri: str | None
    html: str | None


class SAMLLoginData(dict):
    "Class to hold the SAML login data"

    def __init__(self, default_server=None):
        "Initialize the SAML login data"
        super().__init__()
        self.default_server = default_server
        self._cookie_name = ""
        self._cookie_value = ""
        self._interface = ""

    def __setitem__(self, key, value):
        "Set the item in the SAML login data and update cookie and interface"
        super().__setitem__(key, value)
        if key in _SAML_COOKIE_NAME and value:
            self._cookie_name = key
            self._cookie_value = value
            self._interface = _SAML_COOKIE_NAME[key]

    # I need to override the update method not to bypass the __setitem__ method
    def update(self, *args, **kwargs):
        "Update the SAML login data with the given arguments"
        if args:
            if len(args) > 1:
                raise TypeError(f"update expected at most 1 argument, got {len(args)}")
            other = args[0]
            if hasattr(other, "keys"):
                for key in other:
                    self[key] = other[key]
            else:
                for key, value in other:
                    self[key] = value
        for key in kwargs:
            self[key] = kwargs[key]

    def is_ready_to_go(self) -> bool:
        "Check if we have all required SAML headers"
        return bool(self.username and self.cookie_name and self.cookie_value)

    @property
    def username(self):
        "Get the username from the SAML login data"
        return self.get("saml-username", None)

    @property
    def server(self):
        "Get the server from the SAML login data"
        return self.get("server", self.default_server)

    @property
    def cookie_name(self):
        "Get the cookie name from the SAML login data"
        return self._cookie_name

    @property
    def cookie_value(self):
        "Get the cookie value from the SAML login data"
        return self._cookie_value

    @property
    def interface(self):
        "Get the interface from the SAML login data"
        return self._interface


class OpenConnectInfo:
    "Class to hold the OpenConnect info"

    def __init__(
        self,
        connection_info: GPConnectionInfo,
        saml_login_data: SAMLLoginData,
        extra_args: list = [],
    ):
        "Initialize the OpenConnect info"
        self.username = saml_login_data.username
        self.server = connection_info.server
        self.urlpath = f"{connection_info.interface}:{saml_login_data.cookie_name}"
        self.clientos = _CLIENT_OS_TO_OPENCONNECT_OS[connection_info.clientos]
        self.extra_args = extra_args
        self.insecure = connection_info.insecure
        self.user_agent = connection_info.user_agent
        self.cert = connection_info.cert
        self.key = connection_info.key
        self.no_proxy = connection_info.no_proxy
        self.cookie_name = saml_login_data.cookie_name
        self.cookie_value = saml_login_data.cookie_value

    def cli_args(self, include_command=False):
        "Return the OpenConnect command line arguments as a list"
        args = [
            "--protocol=gp",
            "--user=" + self.username,
            "--os=" + self.clientos,
            "--usergroup=" + self.urlpath,
            "--passwd-on-stdin",
            self.server,
        ] + self.extra_args
        if self.insecure:
            args.insert(1, "--allow-insecure-crypto")
        if self.user_agent:
            args.insert(1, "--useragent=" + self.user_agent)
        if self.cert:
            if self.key:
                args.insert(1, "--sslkey=" + self.key)
            args.insert(1, "--certificate=" + self.cert)
        if self.no_proxy:
            args.insert(1, "--no-proxy")
        if include_command:
            args.insert(0, "openconnect")
        return args

    def command_line(self):
        "Return the quoted OpenConnect command line as a string"
        return " ".join(map(quote, self.cli_args(include_command=True)))

    def shell_vars(self):
        "Return a dictionary of shell variables for the OpenConnect command"
        return {
            "HOST": f"https://{self.server}/{self.urlpath}",
            "USER": self.username,
            "COOKIE": self.cookie_value,
            "OS": self.clientos,
        }

    def shell_vars_export(self):
        "Return a string of quoted shell variables for the OpenConnect command"
        return "\n".join(f"{k}={quote(v)}" for k, v in self.shell_vars().items())


def setup_logger(verbose: int):
    "Set the verbosity level for the logger"
    verbosity = min(verbose, max(_VERBOSITY_TO_LOGGING_LEVEL))
    logging_level = _VERBOSITY_TO_LOGGING_LEVEL.get(verbosity, logging.NOTSET)
    logger.setLevel(logging_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging_level)
    formatter = logging.Formatter("%(asctime)-19s [%(levelname)-8s] %(message)s")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def open_external_browser(request_info):
    "Open an external browser"
    # launch external browser for debugging
    logger.info(
        "Got SAML %s, opening external browser for debugging...",
        request_info.method,
    )
    import webbrowser

    if request_info.html:
        uri = "data:text/html;base64," + b2a_base64(request_info.html.encode()).decode()
    else:
        uri = request_info.uri
    webbrowser.open(uri)


def print_stderr(msg):
    "Print a message to stderr"
    print(msg, file=sys.stderr)


def exit_with_error(msg=None):
    "Exit with an error message and code"
    if msg:
        print(msg, file=sys.stderr)
    raise SystemExit(1)


class CLIOpts:
    "Class to hold the CLI options and parse them from the given arguments"

    def __init__(self, args=None):
        "Initialize the CLI options and parse them from the given arguments"
        self._gp_connection_info = None
        self.parser = CLIOpts.parser_factory()
        self.parse(args)  # sets self.args

    def parse(self, args=None):
        "Parse the CLI options from the given arguments"
        self.args = self.parser.parse_args(args)

        if self.args.key and not self.args.cert:
            self.parser.error("--key specified without --cert")

        if self.args.verbose > 2:
            logging.warning("Just one '-v' is enough to increase verbosity")

    @property
    def gp_connection_info(self):
        "Get the GP connection info from the CLI options"
        if self._gp_connection_info is None:
            self._gp_connection_info = GPConnectionInfo(
                uri=self.args.uri,
                insecure=self.args.insecure,
                user_agent=self.args.user_agent,
                cert=self.args.cert,
                key=self.args.key,
                verify=self.args.verify,
                interface=self.args.interface,
                server=self.args.server,
                clientos=self.args.clientos,
                prelogin_extra_fields=dict(x.split("=", 1) for x in self.args.extra),
                cookiejar=(
                    path.expanduser(self.args.cookies) if self.args.cookies else ""
                ),
                no_proxy=self.args.no_proxy,
                retry=self.args.retry,
            )
        return self._gp_connection_info

    @property
    def verbose(self):
        "Get the verbosity level from the CLI options"
        return self.args.verbose

    @property
    def external(self):
        "Get the external browser flag from the CLI options"
        return self.args.external

    @property
    def exec(self):
        "Get the exec mode from the CLI options"
        return self.args.exec

    @property
    def openconnect_extra(self):
        "Get the extra OpenConnect arguments from the CLI options"
        return self.args.openconnect_extra

    @staticmethod
    def parser_factory():
        "Parse command-line arguments"

        p = argparse.ArgumentParser()
        p.add_argument("server", help="GlobalProtect server (portal or gateway)")
        p.add_argument(
            "--no-verify",
            dest="verify",
            action="store_false",
            default=True,
            help="Ignore invalid server certificate",
        )
        x = p.add_mutually_exclusive_group()
        x.add_argument(
            "-C",
            "--cookies",
            default="~/.gp-saml-gui-cookies",
            help="Use and store cookies in this file (instead of default %(default)s)",
        )
        x.add_argument(
            "-K",
            "--no-cookies",
            dest="cookies",
            action="store_const",
            const=None,
            help="Don't use or store cookies at all",
        )
        x = p.add_mutually_exclusive_group()
        x.add_argument(
            "-g",
            "--gateway",
            dest="interface",
            action="store_const",
            const="gateway",
            default="portal",
            help="SAML auth to gateway",
        )
        x.add_argument(
            "-p",
            "--portal",
            dest="interface",
            action="store_const",
            const="portal",
            help="SAML auth to portal (default)",
        )
        g = p.add_argument_group("Client certificate")
        g.add_argument(
            "-c",
            "--cert",
            help="PEM file containing client certificate (and optionally private key)",
        )
        g.add_argument(
            "--key",
            help="PEM file containing client private key (if not included in same file as certificate)",
        )
        x = p.add_mutually_exclusive_group()
        x.add_argument(
            "-v",
            "--verbose",
            default=1,
            action="count",
            help="Increase verbosity of explanatory output to stderr",
        )
        x.add_argument(
            "-q",
            "--quiet",
            dest="verbose",
            action="store_const",
            const=0,
            help="Reduce verbosity to a minimum",
        )
        x = p.add_mutually_exclusive_group()
        x.add_argument(
            "-x",
            "--external",
            action="store_true",
            help="Launch external browser (for debugging)",
        )
        x.add_argument(
            "-P",
            "--pkexec-openconnect",
            action="store_const",
            dest="exec",
            const="pkexec",
            help="Use PolicyKit to exec openconnect",
        )
        x.add_argument(
            "-S",
            "--sudo-openconnect",
            action="store_const",
            dest="exec",
            const="sudo",
            help="Use sudo to exec openconnect",
        )
        x.add_argument(
            "-E",
            "--exec-openconnect",
            action="store_const",
            dest="exec",
            const="exec",
            help="Execute openconnect directly (advanced users)",
        )
        p.add_argument(
            "-u",
            "--uri",
            action="store_true",
            help="Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server",
        )
        p.add_argument(
            "--clientos",
            choices=set(_PYTHON_PLATFORM_TO_CLIENT_OS.values()),
            default=_PYTHON_PLATFORM_TO_CLIENT_OS.get(sys.platform, "Windows"),
            help="clientos value to send (default is %(default)s)",
        )
        p.add_argument(
            "-f",
            "--field",
            dest="extra",
            action="append",
            default=[],
            help='Extra form field(s) to pass to include in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")',
        )
        p.add_argument(
            "-r",
            "--retry",
            default=0,
            action="count",
            help="Retry the SAML login process (workaround for saml-auth-status -1)",
        )
        p.add_argument(
            "--allow-insecure-crypto",
            dest="insecure",
            action="store_true",
            help="Allow use of insecure renegotiation or ancient 3DES and RC4 ciphers",
        )
        p.add_argument(
            "--user-agent",
            "--useragent",
            default="PAN GlobalProtect",
            help="Use the provided string as the HTTP User-Agent header (default is %(default)r, as used by OpenConnect)",
        )
        p.add_argument(
            "--no-proxy", action="store_true", help="Disable system proxy settings"
        )
        p.add_argument(
            "openconnect_extra",
            nargs="*",
            help="Extra arguments to include in output OpenConnect command-line",
        )
        return p


class TLSAdapter(requests.adapters.HTTPAdapter):
    """Adapt to older TLS stacks that would raise errors otherwise.

    We try to work around different issues:
    * Enable weak ciphers such as 3DES or RC4, that have been disabled by default
      in OpenSSL 3.0 or recent Linux distributions.
    * Enable weak Diffie-Hellman key exchange sizes.
    * Enable unsafe legacy renegotiation for servers without RFC 5746 support.

    See Also
    --------
    https://github.com/psf/requests/issues/4775#issuecomment-478198879

    Notes
    -----
    Python is missing an ssl.OP_LEGACY_SERVER_CONNECT constant.
    We have extracted the relevant value from <openssl/ssl.h>.

    """

    def __init__(self, verify=True):
        "Initialize the adapter with the given verification setting."
        self.verify = verify
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        "Initialize the pool manager with the given connection settings."
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.set_ciphers("DEFAULT:@SECLEVEL=1")
        ssl_context.options |= 1 << 2  # OP_LEGACY_SERVER_CONNECT

        if not self.verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        if hasattr(ssl_context, "keylog_filename"):
            sslkeylogfile = environ.get("SSLKEYLOGFILE")
            if sslkeylogfile:
                ssl_context.keylog_filename = sslkeylogfile

        self.poolmanager = urllib3.PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_context=ssl_context
        )


class SAMLHtmlParser(HTMLParser):
    "HTML parser to extract SAML data from the HTML content"

    def init_parser(self) -> None:
        "Initialize the parser state"
        self.comments = []
        self.saml_auth_status = None
        self.recording_saml_auth_status = False

    def handle_comment(self, data: str) -> None:
        "Record any comments in the HTML content"
        self.comments.append(data)

    def handle_starttag(self, tag, attrs) -> None:
        "Start recording the SAML auth status data if we find the right tag"
        if tag == "saml-auth-status":
            self.recording_saml_auth_status = True

    def handle_endtag(self, tag) -> None:
        "Stop recording the SAML auth status data if we were recording it"
        if tag == "saml-auth-status":
            self.recording_saml_auth_status = False

    def handle_data(self, data) -> None:
        "Record the SAML auth status data if we are currently recording it"
        if self.recording_saml_auth_status:
            self.saml_auth_status = data

    def saml_info(self, content):
        "Extract SAML data from the given HTML content"
        self.init_parser()
        self.feed(content)

        info = {}
        for comment in self.comments:
            logger.debug(f"[SAML   ] Found comment in response body: '{comment}'")
            try:
                # xml parser requires valid xml with a single root tag, but our expected content
                # is just a list of data tags, so we need to improvise
                xmlroot = ET.fromstring("<fakexmlroot>%s</fakexmlroot>" % comment)
                # search for any valid first level xml tags (inside our fake root) that could contain SAML data
                for elem in xmlroot:
                    if elem.tag.startswith("saml-") or elem.tag in _SAML_COOKIE_NAME:
                        info[elem.tag] = elem.text
            except ET.ParseError:
                pass  # silently ignore any comments that don't contain valid xml

        if self.saml_auth_status:
            info["saml-auth-status"] = self.saml_auth_status

        return info


class SAMLPreLoginException(Exception):
    "Exception class for prelogin errors"


class SAMLPreLogin:
    "Class to handle the SAML pre-login process"

    def __init__(self, connection_info):
        "Initialize the SAML pre-login process with the given connection info"
        self.connection_info = connection_info  # some attrs will be ignored
        self.endpoint = "https://{}/{}".format(
            self.connection_info.server,
            _SAML_PRELOGIN_PATH[self.connection_info.interface],
        )
        self.data = {
            "tmp": "tmp",
            "kerberos-support": "yes",
            "ipv6-support": "yes",
            "clientVer": 4100,
            "clientos": self.connection_info.clientos,
            **self.connection_info.prelogin_extra_fields,
        }

    def get_login_request_info(self):
        "Get the login request info for the SAML pre-login process"
        if self.connection_info.uri:
            return LoginRequestInfo(
                method="URI", uri=self.connection_info.server, html=None
            )
        return self.query_login_request_info()

    def parse_xml_response(self, content):
        "Parse the XML response content and extract the SAML bits"
        xml = ET.fromstring(content)
        if xml.tag != "prelogin-response":
            raise SAMLPreLoginException(
                "This does not appear to be a GlobalProtect prelogin response\nCheck in browser: {}?{}".format(
                    self.endpoint, urlencode(self.data)
                )
            )
        status = xml.find("status")
        if status and status.text != "Success":
            msg = xml.find("msg")
            if msg:
                wrong_interface_txt = (
                    f"GlobalProtect {self.connection_info.interface} does not exist"
                )
                if msg.text == wrong_interface_txt:
                    raise SAMLPreLoginException(
                        "{} interface does not exist; specify {} instead".format(
                            self.connection_info.interface.title(),
                            "--portal"
                            if self.connection_info.interface == "gateway"
                            else "--gateway",
                        )
                    )
                raise SAMLPreLoginException(
                    f"Error in {self.connection_info.interface} prelogin response: {msg.text}"
                )
        method_node = xml.find("saml-auth-method")
        request_node = xml.find("saml-request")
        if method_node is None or request_node is None:
            raise SAMLPreLoginException(
                "{} prelogin response does not contain SAML tags (<saml-auth-method> or <saml-request> missing)\n\n"
                "Things to try:\n"
                "1) Spoof an officially supported OS (e.g. --clientos=Windows or --clientos=Mac)\n"
                "2) Check in browser: {}?{}".format(
                    self.connection_info.interface.title(),
                    self.endpoint,
                    urlencode(self.data),
                )
            )
        method = method_node.text
        request = a2b_base64(request_node.text).decode()
        return method, request

    def query_login_request_info(self):
        "Query the login request info for the SAML pre-login process"
        # query prelogin.esp and parse SAML bits
        session = requests.Session()
        if self.connection_info.insecure:
            session.mount("https://", TLSAdapter(verify=self.connection_info.verify))
        session.headers["User-Agent"] = self.connection_info.defined_user_agent
        session.cert = self.connection_info.certkey
        logger.info("Looking for SAML auth tags in response to %s...", self.endpoint)
        try:
            response = session.post(
                self.endpoint, verify=self.connection_info.verify, data=self.data
            )
        except Exception as rootex:
            while True:
                if isinstance(rootex, ssl.SSLError):
                    break
                elif not rootex.__cause__ and not rootex.__context__:
                    break
                rootex = rootex.__cause__ or rootex.__context__
            if isinstance(rootex, ssl.CertificateError):
                raise SAMLPreLoginException(
                    "SSL certificate error (try --no-verify to ignore): %s" % rootex
                )
            elif isinstance(rootex, ssl.SSLError):
                raise SAMLPreLoginException(
                    "SSL error (try --allow-insecure-crypto to ignore): %s" % rootex
                )
            else:
                raise
        method, request = self.parse_xml_response(response.content)
        if method == "POST":
            html, uri = request, None
        elif method == "REDIRECT":
            uri, html = request, None
        else:
            raise SAMLPreLoginException("Unknown SAML method (%s)" % method)
        return LoginRequestInfo(method, uri, html)


class SAMLLoginView:
    "Class to handle the SAML login view in a GTK window"

    def __init__(self, connection_info):
        "Initialize the SAML login view with the given connection info"
        self.connection_info = connection_info  # some attrs will be ignored

        self.closed = False
        self.success = False
        self.retried = 0
        self.login_data = SAMLLoginData(default_server=self.connection_info.server)

        self.html_parser = SAMLHtmlParser()
        self.webview_init()  # sets 'self.wview'
        self.window_init()  # sets 'self.window' and connects 'self.wview' to it

    def window_init(self):
        "Initialize the window and connect the webview to it"
        Gtk.init(None)
        self.window = Gtk.Window()
        self.window.resize(500, 500)
        self.window.add(self.wview)
        self.window.show_all()
        self.window.set_title("SAML Login")
        self.window.connect("delete-event", self.close)

    def webview_init(self):
        "Initialize the webview and its context"
        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0
        web_context = WebKit2.WebContext.get_default()
        if not self.connection_info.verify:
            web_context.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        if self.connection_info.cookiejar:
            cookie_manager = web_context.get_cookie_manager()
            cookie_manager.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            cookie_manager.set_persistent_storage(
                self.connection_info.cookiejar, WebKit2.CookiePersistentStorage.TEXT
            )

        self.wview = WebKit2.WebView()

        if self.connection_info.no_proxy:
            data_manager = web_context.get_website_data_manager()
            data_manager.set_network_proxy_settings(
                WebKit2.NetworkProxyMode.NO_PROXY, None
            )

        settings = self.wview.get_settings()
        settings.set_user_agent(self.connection_info.defined_user_agent)
        self.wview.set_settings(settings)
        self.wview.connect("load-changed", self.on_load_changed)
        self.wview.connect("resource-load-started", self.log_resources)

    def load(self, uri, html):
        "Load the given URI or HTML content in the webview"
        if html:
            self.wview.load_html(html, uri)
        else:
            self.wview.load_uri(uri)
        if Gtk.main_level() == 0:
            Gtk.main()

    def close(self, window, event):
        "Callback for delete-event signal, called when window is closed by user"
        self.closed = True
        Gtk.main_quit()

    def log_resources(self, webview, resource, request):
        "Log details of the resource before it starts loading"
        logger.debug(
            "[REQUEST] %s for resource %s",
            request.get_http_method(),
            resource.get_uri(),
        )
        resource.connect("finished", self.log_resource_details, request)

    def log_resource_details(self, resource, request):
        "Log details of the resource after it has finished loading"
        method = request.get_http_method() or "Request"
        uri = resource.get_uri()
        response = resource.get_response()
        message_headers = response.get_http_headers() if response else None
        if message_headers:
            content_type_obj = message_headers.get_content_type()
            content_length = message_headers.get_content_length()
            content_type = content_type_obj[0]
            charset = content_type_obj.params.get("charset")
            content_details = "%d bytes of %s%s for " % (
                content_length,
                content_type,
                ("; charset=" + charset) if charset else "",
            )
        else:
            content_details = ""
        logger.debug("[RECEIVE] %sresource %s %s", content_details, method, uri)

    def log_resource_text(
        self, resource, result, content_type, charset=None, show_headers=None
    ):
        "Log the text content of the resource after it has finished loading"
        data = resource.get_data_finish(result)
        content_details = "%d bytes of %s%s for " % (
            len(data),
            content_type,
            ("; charset=" + charset) if charset else "",
        )
        logger.info("[DATA   ] %sresource %s", content_details, resource.get_uri())
        if show_headers:
            for h, v in show_headers.items():
                logger.info("%s: %s", h, v)
        if charset or content_type.startswith("text/"):
            logger.info(data.decode(charset or "utf-8"))

    def on_load_changed(self, webview, event):
        "Callback for load-changed signal, called when page load event occurs"
        if event != WebKit2.LoadEvent.FINISHED:
            return

        main_resource = webview.get_main_resource()
        uri = main_resource.get_uri()
        response = main_resource.get_response()
        message_headers = response.get_http_headers() if response else None

        logger.info("[PAGE   ] Finished loading page %s", uri)
        uri_obj = urlparse(uri)
        origin = "%s %s" % ("🔒" if uri_obj.scheme == "https" else "🔴", uri_obj.netloc)
        self.window.set_title("SAML Login (%s)" % origin)

        # if no response or no headers (for e.g. about:blank), skip checking this
        if not response or not message_headers:
            return

        content_type_obj = message_headers.get_content_type()

        headers_dict = {}
        message_headers.foreach(
            lambda k, v: operator.setitem(headers_dict, k.lower(), v)
        )
        saml_headers_dict = {
            h: v
            for h, v in headers_dict.items()
            if h.startswith("saml-") or h in _SAML_COOKIE_NAME
        }

        if saml_headers_dict:
            content_type = content_type_obj[0]
            charset = content_type_obj.params.get("charset")
            logger.info("[SAML   ] Got SAML result headers: %r", saml_headers_dict)
            if logger.isEnabledFor(logging.DEBUG):
                main_resource.get_data(
                    None, self.log_resource_text, content_type, charset, headers_dict
                )
            self.login_data.update(saml_headers_dict, server=uri_obj.netloc)
            self.check_done()

        if not self.success:
            logger.debug(
                "[SAML   ] No headers in response, searching body for xml comments"
            )

        main_resource.get_data(None, self.response_callback, content_type_obj)

    def response_callback(self, resource, result, content_type_obj):
        "Callback for resource.get_data, called when body content is available"
        data = resource.get_data_finish(result)
        content = data.decode(content_type_obj.params.get("charset") or "utf-8")
        saml_info = self.html_parser.saml_info(content)
        logger.debug(
            f"[SAML   ] Finished parsing response body for {resource.get_uri()}"
        )

        if saml_info:
            logger.debug(f"[SAML   ] Got SAML result tags: {saml_info}")
            self.login_data.update(
                saml_info, server=urlparse(resource.get_uri()).netloc
            )

        if not self.check_done():
            # Work around timing/race condition by retrying check_done after 1 second
            GLib.timeout_add(1000, self.check_done)

        if (
            saml_info.get("saml-auth-status", "") == "-1"
            and self.retried < self.connection_info.retry
        ):
            # For some reason, retrying the SAML auth process seems to work.
            # I guess that the server is not ready to respond to the SAML auth request.
            # However, starting over with the preloaded cookies seems to work.
            self.retried += 1
            logger.info(
                "[SAML   ] Bad auth. Try again (%s/%s).",
                self.retried,
                self.connection_info.retry,
            )
            prelogin = SAMLPreLogin(self.connection_info)
            login_request_info = prelogin.get_login_request_info()
            logger.info(f"[SAML   ] Got SAML {login_request_info.method}, loading...")
            self.load(login_request_info.uri, login_request_info.html)

    def check_done(self) -> bool:
        "Check if we are done, and if so, quit the main loop"
        if self.login_data.is_ready_to_go():
            logger.info("[SAML   ] Got all required SAML headers, done.")
            self.success = True
            Gtk.main_quit()
            return True
        return False


def report_about_saml_ambiguities(gp_connection_info, login_data):
    "Report ambiguities in the SAML login process"
    if login_data.server != gp_connection_info.server and not gp_connection_info.uri:
        print_stderr(
            "IMPORTANT: During the SAML auth, you were redirected from {0} to {1}."
            " This probably means you should specify {1} as the server"
            " for final connection, but we're not 100% sure about this."
            " You should probably try both.\n"
            "".format(gp_connection_info.server, login_data.server)
        )
    if (
        login_data.interface != gp_connection_info.interface
        and not gp_connection_info.uri
    ):
        print_stderr(
            "IMPORTANT: We started with SAML auth to the {} interface,"
            " but received a cookie that's often associated with the {} interface."
            " You should probably try both.\n".format(
                gp_connection_info.interface,
                login_data.interface,
            )
        )


def openconnect_indented_shell_cmd(openconnect_info):
    "Return the OpenConnect shell command with indentation for a shell script"
    return "    echo {} |\n        sudo {}".format(
        quote(openconnect_info.cookie_value), openconnect_info.command_line()
    )


def report_about_openconnect_command(openconnect_info):
    "Report about the OpenConnect info"
    print_stderr("\nSAML response converted to OpenConnect command line invocation:\n")
    print_stderr(openconnect_indented_shell_cmd(openconnect_info))


def report_about_test_login_script(gp_connection_info, saml_login_data):
    "Report about the test script"
    print_stderr(
        "\nSAML response converted to test-globalprotect-login.py invocation:\n"
    )
    print_stderr(
        "    test-globalprotect-login.py --user={} --clientos={} -p '' \\\n"
        "        https://{}/{} {}={}\n".format(
            quote(saml_login_data.username),
            quote(gp_connection_info.clientos),
            quote(gp_connection_info.server),
            quote(_SAML_AUTH_PATH[gp_connection_info.interface]),
            quote(saml_login_data.cookie_name),
            quote(saml_login_data.cookie_value),
        )
    )


def report_and_launch_openconnect(openconnect_info, exec_mode):
    "Report about the OpenConnect command and launch it with the given exec mode"
    print_stderr(
        "Launching OpenConnect with {}, equivalent to:\n{}".format(
            exec_mode, openconnect_indented_shell_cmd(openconnect_info)
        )
    )
    with tempfile.TemporaryFile("w+") as tf:
        tf.write(openconnect_info.cookie_value)
        tf.flush()
        tf.seek(0)
        # redirect stdin from this file, before it is closed by the context manager
        # (it will remain accessible via the open file descriptor)
        dup2(tf.fileno(), 0)
    cmd = openconnect_info.cli_args(with_command=True)
    if exec_mode == "pkexec":
        cmd = ["pkexec", "--user", "root"] + cmd
    elif exec_mode == "sudo":
        cmd = ["sudo"] + cmd
    execvp(cmd[0], cmd)


def main(args=None):
    "Main function to handle the SAML login process"
    # parse command line arguments
    opts = CLIOpts(args)

    setup_logger(opts.verbose)

    # get SAML request
    prelogin = SAMLPreLogin(opts.gp_connection_info)
    try:
        login_request_info = prelogin.get_login_request_info()
    except SAMLPreLoginException as ex:
        exit_with_error(str(ex))

    if opts.external:
        open_external_browser(login_request_info)
        raise SystemExit

    # Managed browser window for SAML login
    logger.info("Got SAML %s, opening browser...", login_request_info.method)
    saml_login = SAMLLoginView(opts.gp_connection_info)
    # Start interactive GUI loop
    saml_login.load(login_request_info.uri, login_request_info.html)
    # At this point the interactive GUI loop has finished
    if saml_login.closed:
        exit_with_error("Login window closed by user.")
    if not saml_login.success:
        exit_with_error("Login window closed without producing SAML cookies.")
    if saml_login.login_data.cookie_name is None:
        exit_with_error("Didn't get an expected cookie. Something went wrong.")

    if opts.verbose:
        # report to stderr
        report_about_saml_ambiguities(opts.gp_connection_info, saml_login.login_data)

    openconnect_info = OpenConnectInfo(
        opts.gp_connection_info, saml_login.login_data, opts.openconnect_extra
    )

    if opts.verbose:
        # report to stderr
        report_about_openconnect_command(openconnect_info)
        report_about_test_login_script(opts.gp_connection_info, saml_login.login_data)

    if opts.exec:
        # report to stderr and launch openconnect
        report_and_launch_openconnect(openconnect_info, opts.exec)
    else:
        # print shell vars to stdout, so they can be sourced
        print(openconnect_info.shell_vars_export())


if __name__ == "__main__":
    main()
