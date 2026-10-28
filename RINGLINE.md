# ringline-tls

A fork of [rustls](https://github.com/rustls/rustls) maintained for
[ringline](https://github.com/ringline-rs/ringline). The library is named
`ringline_tls`; its API is rustls's.

Upstream: v/0.23.46

## Why

ringline changes the TLS record layer, for example to encrypt into and
decrypt out of its own buffers, and releases those changes on its own
schedule. The design is in ringline's
[docs/rustls-quinn-forks-design.md](https://github.com/ringline-rs/ringline/blob/main/docs/rustls-quinn-forks-design.md).

## Branches and versions

- `ringline/0.23` is the default branch. It starts at rustls's `v/0.23.46`
  tag. Each later commit is a ringline change, a merge of an upstream
  0.23.x release, or a release commit, so
  `git diff <newest merged upstream tag> ringline/0.23` is the whole of the
  fork's changes.
- `ringline-tls` 0.1.x is based on rustls 0.23.x. A 0.1.x release never
  changes the API incompatibly. An API change, or a move to rustls 0.24, is
  a new minor version (0.2.0, ...).
- The `Upstream:` line above names the upstream tag this version contains.
  Each release's notes carry the same line.
- Upstream releases arrive as pull requests from `admin/ringline-update`.
  Merge them with a merge commit, not a squash: the next update merges from
  the upstream tag's commit, which a squash would drop.

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
[SECURITY.md](SECURITY.md)); report one in the fork's own changes to the
ringline maintainers through GitHub's private vulnerability reporting on
this repository.

## License

Apache-2.0, ISC or MIT, as rustls. See the `LICENSE*` files.
