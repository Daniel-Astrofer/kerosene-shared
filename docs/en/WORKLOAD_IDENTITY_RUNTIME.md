# SPIFFE workload identity runtime

`com.kerosene.common.security.workload` is the reusable Java transport layer
for Auth and KFE. It does not own service routes, authorization policy or
deployment manifests.

When enabled, the runtime connects to the SPIFFE Workload API over a Unix
socket, waits for an X.509-SVID and trust bundle, and refuses startup unless the
issued SPIFFE ID exactly matches the configured workload. TLS 1.3 client and
server contexts accept one configured peer SPIFFE ID; `acceptAny` is never used.
SVID and bundle updates remain in memory and are consumed without writing
private keys to disk.

Each service must expose a dedicated internal HTTPS connector and protect its
own internal route prefixes with `InternalServiceAuthenticationFilter`. Public
connectors cannot satisfy the internal-port check. A legacy shared-secret mode
exists only for explicit local compatibility and fails closed when the secret
is absent. Production service gates must require workload identity and reject
that legacy secret.

This library is one layer. Production also requires SPIRE registration,
Workload API socket isolation, NetworkPolicy, immutable images and an end-to-end
handshake test in the target cluster.
