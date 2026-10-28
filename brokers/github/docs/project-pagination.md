# Organization Project item-list pagination readback

`project.projects_list_items_for_org` executes one bounded REST request. It does
not follow pagination automatically. Its generated binding already accepts
`after`, `before`, `per_page`, `q`, and `fields` and declares `pagination: link`.

The upstream projected result remains an array, with exactly the existing item,
content identity and selected-field projections. The existing Agent operation
result object still contains that array as `result.items`. When pagination can
be established safely, that SAME object also contains optional
`result.pagination`:

- `{"has_next":true,"next_after":"<validated opaque cursor>"}` means there is
  another forward page. Submit the same operation, target and noncursor arguments
  with `after` set to that cursor. Do not treat this page as a complete inventory.
- `{"has_next":false}` means this successfully decoded forward response has no
  next relation. This includes a valid empty array with no Link header, or a
  nonempty last page with no Link header or only a validated `prev` relation.
- Missing `pagination` means UNAVAILABLE, never false, empty, terminal or complete.
  Historical receipts and unsupported/invalid pagination also have this form.

There are no totals, inferred counts, raw response headers, or response URLs in
this metadata. `has_next:false` is page-scoped no-next proof, NOT proof that prior
pages were read, that no filters were applied, or that a changing Project was read
as one consistent snapshot. A complete inventory still requires an explicitly
tracked forward traversal starting without a cursor, stable target/filters, every
page retained, and terminal proof. Starting at an arbitrary `after` cursor cannot
establish a complete inventory. Backward (`before`) requests do not produce these
forward facts.

## Narrow validation and compatibility

Only this organization item-list operation with its existing GET/array/Link
binding produces metadata. Other operations, providers, generated projections,
wire types, persistence schemas, permissions, policies and request routing are
unchanged. Existing successful projected array bytes are preserved; unaffected
Agent result bytes are unchanged. The additive sibling uses the already supported
raw result object through the operation store, generated Agent HTTP transport,
Agent client and CLI JSON writer. It does not create a new envelope or API.

A valid nonempty response body must decode as an array and have HTTP status 200.
A synthesized empty result for a blank body is NOT pagination evidence. Transport,
JSON decoding or result-schema failures cannot become successful terminal proof.

The accepted Link subset is deliberately conservative: quoted or unquoted `next`
and `prev`, at most one of each, without extension parameters. Every link must be
absolute, same scheme/host and exact escaped path as the executed request, without
userinfo or fragment. All noncursor query selectors must match the request;
unsupported parameters, duplicate single-valued parameters, changed field arrays,
wrong-direction or looping cursors, ambiguous relations, malformed syntax and
unsupported extensions make the entire metadata unavailable. Multiple header
values and comma-separated links are checked together. A declared Link trailer
also makes metadata unavailable; it is not mistaken for an absent Link header.
No link is fetched.

Bounds: 8192 combined Link bytes, 2048 bytes per link URL, 4096 bytes of request
query, at most 50 repeated `fields` values, and 256 decoded cursor bytes. Cursors
are restricted to the alphanumeric/base64/base64url character subset with trailing
padding and reject common token/JWT-like prefixes. These are safe opaque strings,
not signed URLs or decoded credential data. Unsupported provider cursor formats
remain unavailable rather than being accepted speculatively.

## Existing alternatives inspected

The GitHub-compatible `/api/v3` path forwards and rewrites Link headers but is
restricted to a single repository by `apicompat.RESTMatch.Request`; it does not
serve organization Project inventory or persist operation readback. Widening it
would require unrelated effect authority. SDK installation pagination is internal
to credential discovery and is not Project item inventory. Neither is a substitute
for this operation's maintained receipt.

## Local verification boundaries

`TestProjectPaginationHTTP` exercises synthetic loopback HTTP through the real
authenticated REST client, projection and pagination decoder, including terminal,
malformed, wrong-target, secret-like-header, truncation and unchanged-result cases.
`TestProjectPaginationDurableCLI` exercises the actual broker operation runtime,
store, close/reopen readback, generated Agent client and CLI serialization. It
retains exact existing projected item bytes, proves multi-page next cursors and
explicit no-Link terminal proof, and verifies unavailable/failure cases survive
persistence without fabricating completeness. These are offline fixtures, not
real-provider inventory, deployed behavior, or migration acceptance.
