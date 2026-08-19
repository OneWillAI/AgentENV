# Paused Sandbox Recovery

AgentENV preserves paused-sandbox artifacts when it cannot prove that their
metadata is valid or durably indexed. Startup automatically repairs a missing
or corrupt v2 RocksDB index when its adjacent manifest is valid. It does not
guess through manifest/index disagreement, malformed manifests, or markerless
artifact generations; those items are quarantined on the local worker.

The recovery utility is intentionally host-local and has no HTTP/API surface.
Run it as a host administrator on the worker that owns the persisted-sandbox
disk, with the AgentENV server stopped so it does not race normal persistence:

```sh
sudo aenv-paused-recovery --store /var/lib/aenv/persisted-sandboxes list
sudo aenv-paused-recovery --store /var/lib/aenv/persisted-sandboxes reconcile
```

`reconcile` is non-destructive: it rebuilds only missing or corrupt index
entries from valid manifests. Review `list` output before any removal.

To deliberately discard one quarantined item and its tracked artifacts:

```sh
sudo aenv-paused-recovery --store /var/lib/aenv/persisted-sandboxes \
  purge paused-<id> --yes
```

`purge` is irreversible and is the only automated destructive path for
quarantined paused data.
