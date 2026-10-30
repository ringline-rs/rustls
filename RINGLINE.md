# ringline-tls

A fork of [rustls](https://github.com/rustls/rustls) maintained for
[ringline](https://github.com/ringline-rs/ringline). The library is named
`ringline_tls`; its API is rustls's plus the additions listed under Why.

Upstream: v/0.23.46

## Why

ringline needs changes to the TLS record layer, for example to encrypt into
and decrypt out of its own buffers. The fork carries them and releases them
on its own schedule. A release is the upstream release named on the
`Upstream:` line, renamed, with rustls-webpki 0.103.16 or later, plus these
changes:

- In the unbuffered API, `WriteTraffic::encrypt` has the TLS 1.3 encrypters
  of both providers seal application-data records in the caller's buffer.
  API additions: `MessageEncrypter::encrypt_into` (a provided method
  that defaults to `encrypt` plus a copy) and `OutboundChunks::copy_to_slice`.
- In the unbuffered API, `ReadTraffic::next_record` lends each application-data
  record from the `incoming_tls` buffer it was decrypted in, without a copy.
  The record's bytes are reported in `AppDataRecord::discard`, not in
  `UnbufferedStatus::discard`, so a caller must add the record's discard, as
  rustls documents. A caller that does not add it gets
  `Err(Error::DecryptError)` in `UnbufferedStatus::state` from the next
  `process_tls_records` call. A record that is not read stays at the front of
  the buffer, and `next_record` returns it from the `ReadTraffic` of the next
  `process_tls_records` call; the caller must keep those bytes unchanged
  until then. While a record is lent, `wants_read()` and
  `current_io_state().plaintext_bytes_to_read` on an unbuffered connection do
  not count it.

The design is in ringline's
[docs/rustls-quinn-forks-design.md](https://github.com/ringline-rs/ringline/blob/main/docs/rustls-quinn-forks-design.md).

## Branches and versions

- `ringline/0.23` is the default branch. It starts at rustls's `v/0.23.46`
  tag. Each later commit is a ringline change, a merge of an upstream
  0.23.x release, or a release commit, so
  `git diff <newest merged upstream tag> ringline/0.23` is the whole of the
  fork's changes.
- `ringline-tls` 0.1.x is based on rustls 0.23.x. A 0.1.x release never
  changes the API incompatibly. An incompatible API change, or a move to
  rustls 0.24, is a new minor version (0.2.0, ...). An upstream 0.23.x
  release, which can add API, is a patch version.
- The `Upstream:` line above names the upstream tag this version contains.
  Each release's notes carry the same line.
- Upstream releases arrive as pull requests from `admin/ringline-update`.
  Merge them with a merge commit, not a squash. A squash leaves the upstream
  tag out of the branch's history, so the next merge uses the previous
  upstream tag as its base and conflicts on everything upstream changed
  since.
- A release is published by pushing a `vX.Y.Z` tag
  (`ringline-release.yml`). When ringline's main requires an earlier 0.1.x
  version, the same workflow then opens a pull request against it that
  raises the `ringline-tls` requirement to the release and names the
  upstream advisories the raise fixes (`admin/ringline-raise`).

## Using it

Depend on it under its own name:

```toml
[dependencies]
ringline-tls = "0.1"
```

and use `ringline_tls::` paths, or rename the dependency to keep
`rustls::` paths:

```toml
[dependencies]
rustls = { package = "ringline-tls", version = "0.1" }
```

Crates that implement upstream rustls's traits, such as
`rustls-platform-verifier`, work with upstream rustls only. So do crates
that take rustls types, such as `tokio-rustls`, `hyper-rustls` and `quinn`:
they do not accept a `ringline_tls` config.

## Security

Fixes from upstream rustls are merged and released as patch versions. Report
a vulnerability in upstream rustls to the rustls project (see
[SECURITY.md](https://github.com/ringline-rs/rustls/blob/ringline/0.23/SECURITY.md)); report one in the fork's own changes to the
ringline maintainers through GitHub's private vulnerability reporting on
this repository.

## License

Apache-2.0, ISC or MIT, as rustls. See the `LICENSE*` files.
