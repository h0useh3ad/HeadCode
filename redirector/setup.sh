#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/landing.conf"
TEMPLATE_FILE="${SCRIPT_DIR}/landing.html"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# --- Pre-checks ---
[[ $EUID -eq 0 ]] || error "Run as root: sudo $0"
[[ -f "$CONF_FILE" ]] || error "Config file not found: $CONF_FILE"
[[ -f "$TEMPLATE_FILE" ]] || error "Template not found: $TEMPLATE_FILE"

# --- Load config ---
info "Loading config from ${CONF_FILE}"
source "$CONF_FILE"

# Validate required vars
[[ -n "${LURE_PATH:-}" ]] || error "LURE_PATH is not set in config"
[[ -n "${HEADCODE_BACKEND:-}" ]] || error "HEADCODE_BACKEND is not set in config"

# --- Install Apache ---
if ! command -v apache2 &>/dev/null; then
    info "Installing Apache..."
    apt-get update -qq
    apt-get install -y -qq apache2
fi

# Enable required modules
info "Enabling Apache modules..."
a2enmod proxy proxy_http ssl headers rewrite &>/dev/null

# --- Build landing page from template ---
WEBROOT="/var/www/headcode"
mkdir -p "$WEBROOT"

info "Building landing page..."
sed \
    -e "s|{{PAGE_TITLE}}|${PAGE_TITLE}|g" \
    -e "s|{{HEADING}}|${HEADING}|g" \
    -e "s|{{MESSAGE}}|${MESSAGE}|g" \
    -e "s|{{BUTTON_TEXT}}|${BUTTON_TEXT}|g" \
    -e "s|{{FOOTER}}|${FOOTER}|g" \
    -e "s|{{LURE_PATH}}|${LURE_PATH}|g" \
    "$TEMPLATE_FILE" > "${WEBROOT}/index.html"

info "Landing page written to ${WEBROOT}/index.html"

# --- Generate Apache vhost ---
VHOST_FILE="/etc/apache2/sites-available/headcode.conf"

# Determine SSL config
SSL_BLOCK=""
if [[ -f "${SSL_CERT:-}" && -f "${SSL_KEY:-}" ]]; then
    info "SSL certificates found, configuring HTTPS"
    SSL_BLOCK="
    SSLEngine on
    SSLCertificateFile ${SSL_CERT}
    SSLCertificateKeyFile ${SSL_KEY}
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5"
    LISTEN_PORT="443"
    PROTOCOL="https"
else
    warn "No SSL certs found, configuring HTTP only"
    LISTEN_PORT="80"
    PROTOCOL="http"
fi

cat > "$VHOST_FILE" <<VHOST
<VirtualHost *:${LISTEN_PORT}>
    ServerName ${SERVER_NAME}
    ${SSL_BLOCK}

    DocumentRoot ${WEBROOT}

    # Landing page
    <Directory ${WEBROOT}>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>

    # Proxy the lure path to HeadCode
    ProxyPreserveHost On
    ProxyPass ${LURE_PATH} ${HEADCODE_BACKEND}${LURE_PATH}
    ProxyPassReverse ${LURE_PATH} ${HEADCODE_BACKEND}${LURE_PATH}

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "no-referrer"

    # Block common scanner paths
    RewriteEngine On
    RewriteRule ^/robots\.txt$ - [F,L]
    RewriteRule ^/\.well-known/ - [L]
    RewriteRule ^/favicon\.ico$ - [L]
    RewriteRule ^/${LURE_PATH#/}$ - [L]
    RewriteRule ^/$ - [L]
    RewriteRule ^/index\.html$ - [L]

    # Everything else gets 404
    RewriteRule .* - [R=404,L]

    ErrorLog \${APACHE_LOG_DIR}/headcode_error.log
    CustomLog \${APACHE_LOG_DIR}/headcode_access.log combined
</VirtualHost>
VHOST

info "Apache vhost written to ${VHOST_FILE}"

# --- Enable site ---
a2dissite 000-default &>/dev/null 2>&1 || true
a2ensite headcode &>/dev/null

# Test config
info "Testing Apache configuration..."
apache2ctl configtest

# Restart
info "Restarting Apache..."
systemctl restart apache2

info "Setup complete!"
echo ""
echo "  Landing page: ${PROTOCOL}://${SERVER_NAME}/"
echo "  Lure proxy:   ${PROTOCOL}://${SERVER_NAME}${LURE_PATH} -> ${HEADCODE_BACKEND}${LURE_PATH}"
echo ""
echo "  To customize the landing page:"
echo "    1. Edit ${CONF_FILE}"
echo "    2. Re-run: sudo $0"
echo ""
echo "  Or edit ${WEBROOT}/index.html directly for quick changes."
