# Wi-Fi/Ethernet SRP Infrastructure DNS-SD

This guide describes how to enable and run the Service Registration Protocol
(SRP, RFC 9665) client and server that let Matter Wi-Fi/Ethernet devices publish
and discover DNS-SD services through an infrastructure provider instead of (or in
addition to) multicast DNS.

Two roles are involved:

-   **SRP client** — a Linux Wi-Fi/Ethernet Matter app that registers its DNS-SD
    services (operational `_matter._tcp`, commissionable `_matterc._udp`) with an
    infrastructure provider via a signed DNS `UPDATE`.
-   **SRP server** — a Network Infrastructure Manager (NIM) app
    (`examples/network-manager-app/linux`, intended for a Raspberry Pi) that
    accepts registrations, re-advertises them via mDNS (Advertising Proxy), and
    answers unicast DNS queries against its zone table (Discovery Proxy).

## Configuration flags

The feature is gated by two GN arguments (see
`src/lib/dnssd/wifi_srp.gni`), which map to the corresponding
`CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_CLIENT` /
`CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER` defines:

| GN arg                         | Role         | Default |
| ------------------------------ | ------------ | ------- |
| `chip_enable_wifi_srp_client`  | SRP client   | `false` |
| `chip_enable_wifi_srp_server`  | SRP server   | `false` |

The shared DNS message codec (`SrpDnsMessage`), key management (`SrpKeyPair`) and
`SrpUpdate` sources compile when either flag is set. The client-only
(`InfraDnssdManager`, `SrpUnicastResolver`, Linux `InfraDiscovery`) and
server-only (`InfraDnssdServerImpl`) sources are gated on their respective flag.

## Building the SRP client device

Build any Linux app (for example `lighting-app` or `all-clusters-app`) with the
client flag enabled. Each example has its own `.gn`, so generate with the flag in
`args.gn`:

```bash
scripts/run_in_build_env.sh "cd examples/lighting-app/linux && \
    gn gen out/srp-client --args='chip_enable_wifi_srp_client=true' && \
    ninja -C out/srp-client"
```

No application code change is required: the Linux platform `DnssdImpl` routes
`ChipDnssdPublishService` / `ChipDnssdRemoveServices` /
`ChipDnssdFinalizeServiceUpdate` through `InfraDnssdManager` when a provider is
available, and falls back to the Avahi mDNS path otherwise. On startup the Linux
`AppMain` initializes `InfraDnssdManager` and starts provider discovery (RA
listener + `_dns-sd-srp._tcp` ad-hoc browse).

For on-device deployment build the `linux-arm64` variant instead.

## Building the SRP server device (NIM)

Build the network manager app with the server flag enabled:

```bash
scripts/run_in_build_env.sh "cd examples/network-manager-app/linux && \
    gn gen out/srp-server --args='chip_enable_wifi_srp_server=true' && \
    ninja -C out/srp-server"
```

When enabled, `examples/network-manager-app/linux/main.cpp` instantiates
`InfraDnssdServerImpl`, registers it via `InfraDnssdServer::SetInstance`, calls
`Init` / `Start`, enables the Advertising Proxy and the infrastructure RA flag,
and logs each registration/removal through its delegate.

The server listens on a high UDP port (`53538`) by default so it does not need
root privileges to bind (DNS port 53 would). Clients learn the port from the
provider record discovered via the ad-hoc browse.

## Discovery and resolution

-   **Provider discovery** (client): `src/platform/Linux/InfraDiscovery.cpp`
    opens an ICMPv6 socket to observe Router Advertisements (best effort; usually
    requires `CAP_NET_RAW`/root) and browses `_dns-sd-srp._tcp` over mDNS. Either
    path calls into `InfraDnssdManager`, which selects a provider by priority
    (infrastructure router > SNAC router > ad-hoc).
-   **Unicast resolution** (client): `ChipDnssdUnicastBrowse` /
    `ChipDnssdUnicastResolve` send DNS queries directly to the Discovery Proxy and
    decode PTR/SRV/TXT/AAAA answers. These are implemented on top of the shared
    `Srp::UnicastBrowse` / `Srp::UnicastResolve` helpers.

## Testing

### Unit and single-process loopback (CI)

The unit tests in `src/lib/dnssd/tests` cover the DNS codec round-trip, SIG(0)
sign/verify, client `UPDATE` construction, server parsing/verification, First-
Come-First-Served key enforcement, lease-expiry eviction, the Discovery Proxy
query answers, and a message-level end-to-end loopback (client encodes an
`UPDATE`, the server stores it, and the Discovery Proxy answers a query that
decodes back to the registered values):

```bash
scripts/run_in_build_env.sh "gn gen out/srp-tests \
    --args='chip_build_tests=true chip_enable_wifi_srp_client=true chip_enable_wifi_srp_server=true'"
scripts/run_in_build_env.sh "ninja -C out/srp-tests \
    src/lib/dnssd/tests:TestInfraDnssd.run"
scripts/run_in_build_env.sh "ninja -C out/srp-tests \
    src/lib/dnssd/tests:TestSrpDnsMessage.run"
```

### Two-node LAN (manual)

1.  Run the NIM server on a Raspberry Pi (or a second Linux host) built with
    `chip_enable_wifi_srp_server=true`.
2.  Run a Matter app on the Wi-Fi client host built with
    `chip_enable_wifi_srp_client=true` on the same network.
3.  Commission/advertise from the client and confirm the server logs the
    registration (`SRP server: registered ...`), that the Advertising Proxy
    re-advertises it over mDNS, and that the client can resolve it back through
    the Discovery Proxy.

## Notes and limitations

-   Sending real Router Advertisements from the Pi typically requires
    `CAP_NET_RAW`/root or a `radvd` configuration; for bring-up the ad-hoc mDNS
    browse (`_dns-sd-srp._tcp`) is sufficient for provider discovery.
-   The exact IPv6 RA flag bits used to signal DNS-SD infrastructure availability
    are deployment specific and isolated in
    `src/platform/Linux/InfraDiscovery.cpp`; align them with the final Matter
    infrastructure discovery specification.
```
