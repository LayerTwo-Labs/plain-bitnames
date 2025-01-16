# BitNames

## Install

Check out the repo with `git clone`, and then

```
git submodule update --init
cargo build
```

## BitName data commitments
A BitName can have various data associated with it on-chain;
* IP/port addresses
* Encryption pubkeys
* Verification keys, for checking message signatures
* A 32-byte commitment to arbitrary data

The IP/port addresses and the 32-byte commitment can be used together to commit to more data than is stored on chain.

The IP/port addresses can host a JSON-RPC server with a method `/bitname_commit`, which accepts an optional hex-encoded byte array as an argument.
IPv4 socket addresses are resolved with priority.
`bitname_commit` SHOULD, when the byte array argument is omitted,
return a JSON object that is canonical, in accordance with [RFC-8785](https://datatracker.ietf.org/doc/html/rfc8785).
This object will be hashed using BLAKE3, and the digest compared to
the 32-byte on-chain commitment.
If these match, then any data contained in the JSON object can be considered
to be associated to the BitName.

This protocol is optionally recursive; The JSON object could commit to other commitments, and socket addresses that host a compatible RPC server.
The first RPC call to the server hosted at an IP/port address does not use the
bytes argument, but subsequent calls MAY. How recursive commitments
are resolved is an implementation choice for the resolver.


