# Load Balancer bootstrap

This product does not create or modify OCI Load Balancer resources. Before the
first ACME operation, the customer or IaC must permanently configure:

1. public TCP/HTTP port 80;
2. a route for `/.well-known/acme-challenge/` to the responder private port;
3. a responder backend set and health check;
4. network and WAF exceptions for that challenge path;
5. an HTTPS listener associated manually with the stable OCI certificate OCID.

Do not redirect, authenticate, cache, or challenge the HTTP-01 path. The same
route is reused for every renewal.

## Multiple Load Balancers

The same OCI certificate OCID may be associated manually with multiple existing
HTTPS consumers. Every Load Balancer that serves a domain must route that
domain's challenge path to the responder. The publisher resolves each domain
from DNS and never discovers, creates, changes or stores Load Balancer
resources or addresses.
