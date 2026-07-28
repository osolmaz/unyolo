# go-git Adoption Record

Date: 2026-07-13

unYOLO uses `github.com/go-git/go-git/v5` v5.19.1 behind the shared `gitx`
package for Git pkt-line and SHA-1 packfile behavior. Provider packages do not
import go-git types or parse Git framing themselves.

## Supported Boundary

- Pkt-line scanning and encoding use go-git's canonical implementation.
- Pack inspection supports SHA-1 pack version 2, including OFS deltas, REF
  deltas, and thin packs whose external bases are available from the provider's
  mirror.
- Receive-pack command framing continues to recognize both 40-character SHA-1
  and 64-character SHA-256 object IDs. This does not claim SHA-256 packfile
  support.
- Pack version 3 and SHA-256 packfiles fail closed because go-git v5.19.1 does
  not parse them. They must not be enabled by widening provider-local code.

## Resource Limits

The HF adapter currently allows at most:

- 25 MiB of pack input;
- 1,048,576 objects;
- 16 MiB per inflated object or delta result; and
- 128 MiB of combined inflated pack data and loaded thin-pack bases.

`gitx` preflights every object with go-git's streaming scanner before invoking
the allocating parser. The preflight validates the count, declared and actual
inflated sizes, delta target sizes, checksum, exact trailer position, combined
budget, and context cancellation. go-git then performs canonical object,
checksum, OFS/REF delta, thin-pack, and delta-depth validation. The final parser
stores bounded objects only for the duration of inspection and returns only
commit and tag objects.

The exact trailer check remains unYOLO-owned because go-git's buffered
scanner may read beyond the checksum before its caller can inspect the
underlying reader offset. The small delta-size decoder remains unYOLO-owned
because go-git does not expose its target-size decoder before parser allocation.

## Preservation And Corpus

The checked-in tests cover:

- malformed, oversized, and truncated pkt-lines;
- flush packets and exact receive-pack trailing-byte preservation;
- ordinary SHA-1 packs produced by Git;
- commit and annotated-tag extraction;
- a real thin pack that fails without and succeeds with an external base;
- pack, object-count, object-size, and combined-inflation limits;
- cancellation, bad checksums, and trailing pack data; and
- existing HF force-push classification, ancestry, refusal, and side-band
  report behavior.

The dependency adds one direct module and brings the `gitx` dependency closure
to 152 standard-library and module packages on the current toolchain. The
closure includes go-billy, gcfg, securejoin, sha1cd, and their small support
modules. This cost replaces the broker-local pkt-line, packfile, object, and
delta implementations and centralizes future Git security updates.

Run the relevant verification with:

```sh
go test -race ./gitx ./brokers/huggingface/internal/gitproxy
./scripts/check-architecture.sh
```
