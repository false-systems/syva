# syva-adapter-api

`syva-api` is a thin REST proxy in front of the local `syva-core` Unix-socket API.

Start:

```bash
syva-api \
    --listen 0.0.0.0:8080 \
    --core-socket /run/syva/syva-core.sock
```

Endpoints:
- `POST /v1/zones`
- `GET /v1/zones`
- `GET /v1/zones/{name}`
- `PUT /v1/zones/{name}`
- `DELETE /v1/zones/{name}`
- `GET /healthz`
