"""Offline checks for direct-access.sh (dsite): syntax, rendered Nginx,
fail2ban and firewall plans and config validation. Never
touches the system, production or Docker."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("direct-access.sh")

NEWAPI_SITE = """SITE_NAME=gateway
DOMAIN=api.example.com
UPSTREAM=127.0.0.1:3000
SOURCE=new-api
PRESET=newapi
API_RATE=20
API_BURST=40
CONN_LIMIT=60
BODY_MB=128
PROXY_TIMEOUT=900
BUFFERING=off
AUTH_PATHS=^/api/(user/(login|register|passkey/login)|verification|reset_password|oauth/)
AUTH_RATE=10
AUTH_BURST=10
HEALTH_PATH=/api/status
HSTS=on
DIRECT={direct}
"""

WEB_SITE = """SITE_NAME=docs
DOMAIN=docs.example.com
UPSTREAM=127.0.0.1:3100
SOURCE=docmost-proxy-1
PRESET=web
API_RATE=10
API_BURST=50
CONN_LIMIT=30
BODY_MB=20
PROXY_TIMEOUT=120
BUFFERING=on
AUTH_PATHS=
AUTH_RATE=10
AUTH_BURST=10
HEALTH_PATH=/
HSTS=on
DIRECT=off
"""


def make_root(sites, global_conf=""):
    root = Path(tempfile.mkdtemp(prefix="direct-sites-test-"))
    (root / "sites").mkdir()
    (root / "global.conf").write_text(global_conf)
    for name, text in sites.items():
        (root / "sites" / f"{name}.conf").write_text(text)
    return root


def run(args, root, **env):
    run_env = {**os.environ, "DIRECT_SITES_ROOT": str(root), **env}
    return subprocess.run(["bash", str(SCRIPT), *args], env=run_env,
                          capture_output=True, text=True)


def render(root, **env):
    out = Path(tempfile.mkdtemp(prefix="direct-sites-out-"))
    result = run(["--render", str(out)], root, **env)
    return result, out


class DirectAccessTest(unittest.TestCase):
    def test_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_two_sites_one_on(self):
        root = make_root({"gateway": NEWAPI_SITE.format(direct="on"), "docs": WEB_SITE})
        result, out = render(root)
        self.assertEqual(result.returncode, 0, result.stderr)
        api = (out / "direct-site-gateway.conf").read_text()
        for needle in (
            "server_name api.example.com;",
            "proxy_pass http://127.0.0.1:3000;",
            "proxy_set_header X-Forwarded-For $remote_addr;",
            "proxy_set_header Upgrade $http_upgrade;",
            "proxy_buffering off;",
            "proxy_read_timeout 900s;",
            "client_max_body_size 128m;",
            "limit_conn ds_gateway_conn 60;",
            "limit_req zone=ds_gateway_auth burst=10 nodelay;",
            "limit_req zone=ds_gateway_req burst=40 nodelay;",
            'location ~ "^/api/(user/(login|register|passkey/login)|verification|reset_password|oauth/)"',
            "access_log /var/log/nginx/direct-site-gateway.access.log;",
            "error_log /var/log/nginx/direct-sites.error.log warn;",
            "return 301 https://$host$request_uri;",
        ):
            self.assertIn(needle, api)
        self.assertNotIn("$proxy_add_x_forwarded_for", api)
        docs = (out / "direct-site-docs.conf").read_text()
        self.assertNotIn("listen 443", docs)
        self.assertIn("return 444;", docs)
        self.assertIn("/.well-known/acme-challenge/", docs)
        http = (out / "direct-sites-http.conf").read_text()
        self.assertIn("zone=ds_gateway_req:10m rate=20r/s", http)
        self.assertIn("zone=ds_gateway_auth:10m rate=10r/m", http)
        self.assertIn("zone=ds_docs_req:10m rate=10r/s", http)
        self.assertNotIn("ds_docs_auth", http)
        default = (out / "direct-sites-default.conf").read_text()
        self.assertIn("ssl_reject_handshake on;", default)
        self.assertIn("listen 80 default_server;", default)
        self.assertIn("ufw allow 443/tcp", (out / "firewall-ufw.txt").read_text())

    def test_web_site_when_on_keeps_buffering_and_no_auth_zone(self):
        root = make_root({"docs": WEB_SITE.replace("DIRECT=off", "DIRECT=on")})
        _, out = render(root)
        docs = (out / "direct-site-docs.conf").read_text()
        self.assertIn("listen 443 ssl http2;", docs)
        self.assertNotIn("proxy_buffering off;", docs)
        self.assertNotIn("ds_docs_auth", docs)
        self.assertIn("client_max_body_size 20m;", docs)

    def test_all_off_closes_https(self):
        root = make_root({"gateway": NEWAPI_SITE.format(direct="off")})
        _, out = render(root, RENDER_SSH_PORTS="2222 22")
        self.assertNotIn("listen 443", (out / "direct-sites-default.conf").read_text())
        self.assertNotIn("listen 443", (out / "direct-site-gateway.conf").read_text())
        plan = (out / "firewall-ufw.txt").read_text()
        self.assertIn("ufw delete allow 443/tcp", plan)
        self.assertIn("ufw allow 2222/tcp", plan)
        self.assertIn("ufw allow 22/tcp", plan)
        self.assertIn("ufw default deny incoming", plan)
        self.assertNotIn("3000", plan)
        firewalld = (out / "firewall-firewalld.txt").read_text()
        self.assertIn("--remove-port=443/tcp", firewalld)

    def test_variants(self):
        root = make_root({"gateway": NEWAPI_SITE.format(direct="on")}, "FW_KEEP=8443/tcp\n")
        _, out = render(root, RENDER_IPV6="0", RENDER_HTTP2NEW="1")
        api = (out / "direct-site-gateway.conf").read_text()
        self.assertIn("http2 on;", api)
        self.assertNotIn("ssl http2", api)
        self.assertNotIn("[::]", api)
        self.assertIn("ufw allow 8443/tcp", (out / "firewall-ufw.txt").read_text())

    def test_fail2ban_jail(self):
        root = make_root({}, "F2B_IGNORE=198.51.100.7\n")
        _, out = render(root, RENDER_SSH_PORTS="2222")
        jail = (out / "direct-sites.local").read_text()
        self.assertIn("[sshd]\nenabled = true\nbackend = systemd\n"
                      "banaction = nftables-multiport\naction = %(action_)s\nport = 2222", jail)
        self.assertIn("ignoreip = 127.0.0.1/8 ::1 198.51.100.7", jail)
        self.assertIn("logpath = /var/log/nginx/direct-sites.error.log", jail)

    def test_version_and_help(self):
        root = make_root({})
        result = run(["version"], root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^dsite \d{4}\.\d{2}\.\d{2}")
        self.assertIn("dsite update", run(["--help"], root).stdout)

    def test_install_script_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT.with_name("install.sh"))], check=True)

    def test_invalid_config_rejected(self):
        bad_sites = (
            NEWAPI_SITE.format(direct="on").replace("DOMAIN=api.example.com",
                                                    "DOMAIN=evil.com;include /etc/passwd"),
            NEWAPI_SITE.format(direct="on").replace("127.0.0.1:3000", "10.0.0.1:3000"),
            NEWAPI_SITE.format(direct="on").replace("API_RATE=20", "API_RATE=0"),
            NEWAPI_SITE.format(direct="on").replace("SITE_NAME=gateway", "SITE_NAME=other"),
            NEWAPI_SITE.format(direct="on").replace("AUTH_PATHS=^/api/", 'AUTH_PATHS="; return 200 x; #'),
            NEWAPI_SITE.format(direct="on") + "UNKNOWN=1\n",
        )
        for bad in bad_sites:
            result, _ = render(make_root({"gateway": bad}))
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertTrue("无效" in result.stderr or "不一致" in result.stderr, result.stderr)
        result, _ = render(make_root({}, "FW_KEEP=3000\n"))
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
