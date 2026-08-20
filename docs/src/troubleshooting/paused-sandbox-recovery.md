# Paused Sandbox Recovery

AgentENV preserves paused-sandbox artifacts when it cannot prove that their
metadata is valid or durably indexed. Startup automatically repairs a missing
or corrupt v2 RocksDB index when its adjacent manifest is valid. It does not
guess through manifest/index disagreement, malformed manifests, or markerless
artifact generations; those items are quarantined on the local worker. A
quarantined leftover does not prevent the worker from booting: startup
releases the create-idempotency key after recording the quarantine, and
continues serving new sandboxes. `purge` is only required to discard the
retained files.

Resume drops the paused index but keeps the last memory generation. The next
Stop still needs that `mem_image.json` as the parent layer list. A later
pause retires the replaced generation; destroy removes the last copy.

The recovery utility is intentionally host-local and has no HTTP/API surface.
Run it as a host administrator on the worker that owns the persisted-sandbox
disk, with the AgentENV server stopped so it does not race normal persistence.
Hambody worker releases install it at
`/opt/agentenv/current/worker/bin/aenv-paused-recovery`; standalone AgentENV
Linux packages install it at `/usr/local/sbin/aenv-paused-recovery`.
Use the path present on the host:

```sh
sudo /opt/agentenv/current/worker/bin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes list
sudo /opt/agentenv/current/worker/bin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes reconcile
```

`reconcile` is non-destructive: it rebuilds only missing or corrupt index
entries from valid manifests. Review `list` output before any removal.

To deliberately discard one quarantined item and its tracked artifacts:

```sh
sudo /opt/agentenv/current/worker/bin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes \
  purge paused-<id> --yes
```

`purge` is irreversible and is the only automated destructive path for
quarantined paused data.
