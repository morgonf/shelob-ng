# Juice Shop + CSP sidecar adapter
#
# Builds on top of the official Juice Shop image.
# The CSP adapter starts a second HTTP server on port 8080 (inside the
# same process) that exposes POST /csp/reset and GET /csp/dump.
#
# NODE_OPTIONS="--require ..." is the standard way to inject code before the
# application entry point without modifying the application itself.

FROM bkimminich/juice-shop:latest

# Copy the CSP adapter into the image.
COPY adapter.js /juice-shop/csp-adapter.js

# Instruct Node.js to load the adapter before any application code.
# This works because Juice Shop starts with: node build/app.js
ENV NODE_OPTIONS="--require /juice-shop/csp-adapter.js"

# Juice Shop: 3000  |  CSP sidecar: 8080
EXPOSE 3000 8080
