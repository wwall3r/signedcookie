# Signed Cookie

This implements signed cookies in the same way as [gleam](https://github.com/gleam-lang/crypto/blob/v1.3.0/src/gleam/crypto.gleam#L75)
and elixir-plug in order to be easily compatible with those libraries.

Additionally, the payload of the cookie is JSON, allowing for multiple values to
be stored in a single cookie in a format easily read by other languages.

