# Publication and egress hardening

This page describes the guarantees behind the security fixes in this branch.

## Committed generations

A refresh writes one directory per publication:

```
data/generations/<id>/public/ssl_results.json
data/generations/<id>/public/domain_results.json
data/generations/<id>/public/history.json
data/generations/<id>/public/status.json, expiries.ics, badges/ (when available)
data/generations/<id>/private/alert_state.json
data/generations/<id>/.complete.json
data/commits/<id>.json
data/current.json
```

1. Every public artifact and the initial private alert checkpoint are written
   into a staging directory.
2. Modified directories are synced bottom-up (nested directories such as
   `public/badges/` before their parent, then the staging root), the directory
   is sealed with `.complete.json` (SHA-256 for each public file and the
   checkpoint), and renamed into `generations/`. The new `generations/` entry
   and the initial `commits/` and `generations/` entries in `data/` are fsynced.
3. A durable commit record `commits/<id>.json` is then written atomically. It
   binds the generation ID to the exact SHA-256 of `.complete.json`; the record
   file and the `commits/` directory entry are fsynced before the convenience
   `current.json` pointer is replaced. A sync failure before that point aborts
   the publication and removes the uncommitted directory and any record it may
   have written.
4. Recovery reads commit records, newest first, and verifies the record against
   the manifest and every public file. Record identity comes only from a strict,
   single-component `g-<lowercase-id>.json` filename; the payload `generation`
   must equal that filename ID before the record is trusted. A sealed directory
   with no record is an uncommitted orphan: it is removed and never served. A
   missing, corrupt or orphan-pointing `current.json` is repaired from a valid
   record; if records exist but none verify, the service fails closed and
   serves no generation.
   A readable but schema-invalid, mismatched or unverifiable record is retained
   as evidence: it suppresses legacy migration and is skipped so an older valid
   record can still be selected. A read-dir, entry or record-file I/O error is
   different: recovery fails closed and **does not** migrate legacy files or
   delete any generation from that partial view.
5. Legacy migration runs only when a complete enumeration finds no commit
   record file at all, including readable invalid records. It copies the legacy
   `public/` tree and `private/alert_state.json` into a generation, syncs the
   nested trees, writes and fsyncs the commit record, and leaves the legacy
   files in place. Pending alert replays and history therefore survive the
   upgrade.
6. Pruning uses the same strict filename/payload identity and only deletes an
   old generation whose record and complete manifest still verify. The
   retention limit counts only generations that pass the same eligibility
   checks as recovery. The current generation is always protected, the newest
   configured number of usable generations is retained, and unknown, invalid,
   mismatched or unverifiable entries are preserved independently. A commit
   record is removed only after its generation directory has been removed
   successfully.
7. `/readyz` is `200` only for a generation whose commit record,
   `ssl_results.json`, `domain_results.json`, `history.json` and alert
   checkpoint all verify as one coherent snapshot. A run in flight never
   replaces the last ready generation.

Delivery advances `private/alert_state.json` after each acknowledged batch. The
renamed checkpoint file and its private parent directory are fsynced. That file
is intentionally allowed to change after commit; the public manifest stays
immutable for the lifetime of the generation.

## Scheduler writer slot

Publication and Discord delivery run on blocking workers. If the run deadline
fires, the scheduler still joins the worker before releasing the single refresh
slot, so a timed-out writer cannot overlap the next run. A run summary reports
`published`, `publish_error`, `delivered`, `delivery_error` and
`deadline_exceeded` independently.

Pending alert events are retained only when Discord is enabled and a valid
webhook is configured. With delivery disabled or the webhook missing, the
checkpoint still advances its observations but clears undelivered events, so
`pending_events` cannot grow without bound. `SSL_CHECK_TIMEOUT` is validated as
a finite, positive duration no greater than one day before conversion; invalid
values fall back to the default instead of panicking.

## DNS

`hickory-proto` is `0.26.3`, above the fixed release for RUSTSEC-2026-0491. Both
UDP and TCP replies are rejected unless the transaction ID, QR bit, opcode and
the single question match the request. UDP ignores non-matching datagrams until
the read deadline. The answer section and AD bit are read only after that check.

## Registration egress

RDAP, IANA bootstrap, `.lk` API and WHOIS traffic is restricted to public
unicast destinations:

- URLs must be `https` with no embedded credentials.
- The custom ureq agent disables inherited environment proxies (`HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) so a proxy cannot move the connection
  away from the resolver policy.
- The custom ureq resolver resolves the hostname, filters loopback, private,
  link-local, shared, reserved, documentation, multicast and transition ranges,
  and returns only the vetted addresses. ureq connects to those pinned
  addresses, so a later DNS answer cannot redirect the socket.
- Redirects are followed manually, three at most, and every hop is revalidated
  and re-resolved through the same resolver.
- A WHOIS referral from IANA must be a hostname or IP literal; alternative
  ports are refused. The WHOIS client resolves the referral, filters it, and
  dials only a validated public address.

Certificate monitoring is separate: configured TLS targets and private CA
material continue to work exactly as before, including private addresses.
