# syva-adapter-file

`syva-file` reconciles a directory of TOML policy files into the local
`syva-core` Unix-socket API. Each `*.toml` filename becomes the zone name.

Start:

```bash
syva-file \
  --policy-dir /etc/syva/policies \
  --core-socket /run/syva/syva-core.sock
```

Notes:

- `syva-file verify` validates TOML policy files without connecting to core.
- The adapter reconciles zones, host paths, and mutual communication pairs.
- Automatic container membership watching is not wired yet. Containers must be
  attached through `syva.core.v1 AttachContainer` until that integration lands.
