# Container & Cloud Runway

1. **Shift left on images** — scan base images in CI before pushing to registry.
2. **Immutable deployments** — never exec into containers; redeploy on config changes.
3. **Network segmentation** — default-deny network policies between namespaces.
4. **Observability** — log all API server requests, enable audit logging.
5. **Serverless** — validate every event input; set function memory/timeout limits.

Reference: [OWASP Container Security](https://github.com/OWASP/Docker-Security), [Cloud-Native Top 10](https://github.com/OWASP/Cloud-Native-Application-Security-Top-10)