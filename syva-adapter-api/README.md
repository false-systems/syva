# syva-adapter-api

`syva-api` is a thin REST proxy in front of `syva-cp` `ZoneService`.

Start:

```bash
syva-api \
    --listen 0.0.0.0:8080 \
    --cp-endpoint http://syva-cp.syva-system.svc:50051 \
    --team-id 00000000-0000-0000-0000-000000000000
```

Endpoints:
- `POST /v1/zones`
- `GET /v1/zones`
- `GET /v1/zones/{name}`
- `PUT /v1/zones/{name}`
- `DELETE /v1/zones/{name}`
- `GET /healthz`
