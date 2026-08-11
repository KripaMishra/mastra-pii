# Deploying the Presidio analyzer (Docker)

```bash
docker compose -f deploy/docker-compose.yml up -d
# wait for health (image pulls ~2 GB first run; en_core_web_lg loads at boot)
curl -s http://localhost:3000/healthz
```

Analyzer listens on `http://localhost:3000`. The package's `RemotePresidioAdapter`
points at this URL (or a deployed copy behind an auth gateway — pass tokens via
`headers`). In your app, wire the URL from an env var:

```ts
createLayeredPii({ presidio: { url: process.env.PRESIDIO_URL ?? 'http://localhost:3000' } });
```

The `test-ui/` API function reads `PRESIDIO_URL` automatically — set it in the
deployment container to switch the test console to the remote engine.

Useful endpoints: `POST /analyze` (typed spans), `GET /healthz`. Anonymization is
done client-side in the package (analyze-only design, see
`docs/presidio-adapter-plan.md`).

```bash
docker compose -f deploy/docker-compose.yml down      # stop
docker compose -f deploy/docker-compose.yml logs -f   # tail
```

Sizing note: the analyzer loads spaCy `en_core_web_lg` (~600 MB RAM). Fine for a
single agent workload; scale horizontally behind a load balancer for throughput.
