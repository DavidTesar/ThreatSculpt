# Security response headers for every route class the dashboard serves.
#
# This lives in its own file and is `include`d into the server block AND into each
# location because of an nginx rule that is easy to get wrong: `add_header` is
# inherited from an outer block only while the inner block declares no `add_header`
# of its own. A single `add_header Cache-Control ...` in a location silently drops
# every inherited security header for that location. Declaring them once at server
# level therefore does not work — the SPA locations set Cache-Control, so they would
# be served bare while only the /api proxy got protected.
#
# `always` makes them apply to error responses too, not just 2xx/3xx.

add_header X-Content-Type-Options nosniff always;

# frame-ancestors below is the control that modern browsers honour; X-Frame-Options
# stays for pre-CSP3 clients. Both say the same thing: never framed.
add_header X-Frame-Options DENY always;

add_header Referrer-Policy strict-origin-when-cross-origin always;

# No feature this dashboard uses needs any of these, so deny them outright.
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;

# HSTS is ignored by browsers on a plain-HTTP response, so it is a no-op when this
# container is reached over http:// — including behind a TLS terminator that talks
# http to us, where it still reaches the browser and takes effect. `preload` is
# deliberately omitted: submitting to the preload list is a hard-to-reverse
# commitment for every subdomain and is the deployer's decision, not the image's.
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# The bundle is entirely self-hosted: no CDN, no web fonts, no analytics, no
# external images, and the API is same-origin via the /api proxy below. So
# 'self' covers everything the app genuinely loads.
#
#   script-src 'self'      — no inline script at all. The pre-paint theme boot used
#                            to be inline in index.html; it now lives in
#                            /theme-init.js precisely so this can stay clean.
#   style-src  'unsafe-inline'
#                          — unavoidable: React inline `style={{...}}` attributes are
#                            used throughout, and CSP has no way to allow style
#                            attributes without allowing inline <style> in browsers
#                            that lack style-src-attr. The usual escalation from CSS
#                            injection is exfiltration to an attacker origin, which
#                            default-src/img-src 'self' already blocks.
#   img-src    data:       — for inline SVG/PNG data URIs.
#   frame-ancestors 'none' — the clickjacking control that actually matters here:
#                            revoke-agent and delete-network are one click each.
#
# If VITE_API_BASE is ever pointed at a cross-origin API, connect-src must gain that
# origin or every request will be blocked.
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;
