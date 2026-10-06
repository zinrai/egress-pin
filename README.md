# egress-pin

Pin the outbound traffic of a process's network namespace to one IP address.

Once pinned, every connection the namespace opens is dropped unless it goes to
that address. Everything in the namespace is covered, whatever is running in
it now or later. Connections made to it from outside can still be answered.

It runs once and exits: 0 once the rules are in place, anything else if they
could not be put there. Nothing keeps running.

## Usage

```
egress-pin --pid 12345 --ip 10.0.0.12
```

- `--pid` is any process in the namespace to pin.
- `--ip` is the one IPv4 or IPv6 address the namespace may connect to.

Both are required and both are taken once. A host name, a network or an empty
value for `--ip` is refused.

Running it again on the same namespace replaces the address rather than adding
a second one.

It pins the one namespace it is given. Whatever gets a new namespace, such as
by restarting, is not pinned. Run egress-pin as part of starting whatever it
pins, so that it runs again each time, and treat its failure as a failure to
start, so that nothing is left running unpinned.

## What gets through

Once pinned, the namespace's outbound traffic is dropped except for

- anything on the loopback interface,
- replies to connections made to it from outside,
- anything to the `--ip` address.

The rules are table `inet egress-pin` in the namespace's own nftables ruleset,
not the host's. They go when the namespace goes, and a process inside it
without `CAP_NET_ADMIN` cannot take them out.

## Requires

- A Linux kernel with nftables.
- Root, or the capabilities to enter another process's network namespace and
  change its nftables ruleset.

## License

This project is licensed under the [MIT License](LICENSE).
