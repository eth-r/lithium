lithium
====

Cryptography that's slightly less likely to blow up on you

**This library is not production-ready and should not be used for purposes
where cryptographic failure may endanger anyone's life, liberty or pursuit of
happiness. The API and implementation will both change unpredictably until
release.**

A libsodium wrapper that aims to make it as hard as possible to shoot yourself
in the foot, and thus make it as easy as possible to use crypto in your
software.

The `Crypto.Lithium.*` modules expose an API designed to make all the choices
for you, and remove as many pitfalls as possible. For example, nonce handling
is a source of unnecessary complexity and danger, and has thus been completely
removed from the interface.

The `Crypto.Lithium.Unsafe.*` modules expose mostly raw libsodium functionality
with a reasonable type system, but in a complex or risky way users of the
library should not need to have to deal with.

Requires libsodium 1.0.15 or later
