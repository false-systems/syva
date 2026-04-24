# syva-cp-client

Client library for the syva control plane. Used by `syva-core` to:

- register as a node
- send heartbeats
- subscribe to assignment updates
- report applied or failed assignment state

This crate is a thin typed wrapper over the tonic-generated client from
`syva-proto`. It does not implement reconcile logic. That belongs to the
consumer.
