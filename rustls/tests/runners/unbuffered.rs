// This fork names its library `ringline_tls`; tests and benches keep the
// `rustls::` paths upstream uses.
extern crate ringline_tls as rustls;

#[macro_use]
mod macros;

#[cfg(feature = "ring")]
#[path = "."]
mod tests_with_ring {
    provider_ring!();

    #[path = "../unbuffered.rs"]
    mod tests;
}

#[cfg(feature = "aws_lc_rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    provider_aws_lc_rs!();

    #[path = "../unbuffered.rs"]
    mod tests;
}
