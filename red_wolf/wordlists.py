"""
wordlists.py
------------
Default path lists used for the "wordlist-based discovery" mode.
These are generic, commonly-seen path patterns for:
  - REST / internal APIs
  - Admin panels
  - File / document download endpoints
  - Backup / config leftovers

They are intentionally GENERIC (not tied to any specific product like
Equella). Add product-specific paths via a custom wordlist file at
runtime instead of editing this file.
"""

# Common API-ish paths that sometimes forget to enforce auth
API_PATHS = [
    "api/search",
    "api/search?q=&start=0&length=10",
    "api/items",
    "api/item",
    "api/users",
    "api/user",
    "api/admin",
    "api/config",
    "api/status",
    "api/health",
    "api/v1/users",
    "api/v1/admin",
    "api/export",
    "api/files",
    "api/download",
    "api/reports",
    "api/settings",
    "api/internal",
    "api/debug",
    "graphql",
    "api/v2/users",
    "api/v2/admin",
    "api/v2/config",
    "api/v2/export",
    "api/search.json",
    "api/users.json",
    "api/docs",
    "api/swagger",
    "api/swagger.json",
    "rest",
    "rest/api",
    "rest/v1",
    "internal/api",
    "internal/status",
    "health",
    "status",
]

# Admin / management UI paths
ADMIN_PATHS = [
    "admin",
    "admin/",
    "admin/login.do",
    "admin/index.do",
    "admin/dashboard",
    "administrator",
    "manage",
    "management",
    "console",
    "cpanel",
    "admin/api",
    "admin/api/users",
    "admin/config",
    "admin/settings",
    "login",
    "user/login",
    "dashboard",
    "portal",
    "backend",
    "backoffice",
    "staff",
]

# File / document download endpoints
FILE_PATHS = [
    "download",
    "downloads",
    "files",
    "file",
    "export",
    "exports",
    "backup",
    "backups",
    "uploads",
    "media",
    "attachments",
    "documents",
    "reports/export",
    "download/file",
    "download/document",
    "download/export",
    "api/downloads",
    "api/attachments",
    "api/documents",
    "public/uploads",
    "static",
    "assets",
    "webdav",
]

# Leftover / misconfiguration-prone paths
MISC_PATHS = [
    ".git/config",
    ".env",
    ".env.local",
    "config.json",
    "config.yaml",
    "swagger.json",
    "swagger-ui.html",
    "openapi.json",
    "actuator",
    "actuator/health",
    "actuator/env",
    ".well-known/security.txt",
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "phpinfo.php",
    "server-status",
    "server-info",
    "debug",
    "trace",
    "version",
    "healthcheck",
    "metrics",
    "actuator/info",
    "actuator/metrics",
    "api-docs",
    "docs",
    "redoc",
]

DEFAULT_WORDLIST = sorted(set(API_PATHS + ADMIN_PATHS + FILE_PATHS + MISC_PATHS))

# High-signal paths for the interactive quick scan. This avoids spending
# most of the run on generic UI and legacy paths with little recon value.
FOCUSED_WORDLIST = [
    "api",
    "api/search",
    "api/items",
    "api/users",
    "api/config",
    "api/export",
    "api/files",
    "api/download",
    "api/v1/users",
    "api/v1/admin",
    "api/internal",
    "graphql",
    "swagger.json",
    "openapi.json",
    "api-docs",
    "admin",
    "admin/dashboard",
    "administrator",
    "manage",
    "console",
    "download",
    "downloads",
    "files",
    "file",
    "export",
    "exports",
    "uploads",
    "attachments",
    "documents",
    ".env",
    ".env.local",
    "config.json",
    "actuator/env",
    "actuator/metrics",
    "debug",
    "metrics",
    "server-status",
]


def get_wordlist(profile: str = "balanced"):
    """Return a built-in wordlist for a focused, balanced, or full scan."""
    if profile == "focused":
        return list(FOCUSED_WORDLIST)
    if profile in {"balanced", "full", "comprehensive"}:
        return list(DEFAULT_WORDLIST)
    raise ValueError(f"Unknown scan profile: {profile}")


def load_wordlist_from_file(path: str):
    """
    Read a custom wordlist from disk: one path per line.
    Blank lines and lines starting with '#' are ignored.
    Leading slashes are stripped since urljoin handles joining.
    """
    paths = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(line.lstrip("/"))
    return paths
