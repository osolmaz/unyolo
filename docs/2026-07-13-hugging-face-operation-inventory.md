# Hugging Face Operation Inventory

Date: 2026-07-13

Status: implementation baseline

## Purpose

This document defines the complete Hugging Face capability surface that the HF
broker cutover must account for. It replaces an open-ended promise to inventory
the provider later.

"Complete" means every remotely meaningful operation exposed by either of
these official surfaces at the pinned baseline:

- the live [Hugging Face Hub OpenAPI document](https://huggingface.co/.well-known/openapi.json),
  fetched on 2026-07-13: 251 paths, 311 HTTP operations, SHA-256
  `38e593b0d695faf2f587016a19446bfbbedad09493e0e6334b5c6bfcad7ff247`;
- [`huggingface/huggingface_hub`](https://github.com/huggingface/huggingface_hub/tree/c4ed724b7f917e5c5a79ca78abcf882c3c7dda91)
  commit
  `c4ed724b7f917e5c5a79ca78abcf882c3c7dda91`, dated 2026-07-09: 161 public
  `HfApi` methods, 33 public `InferenceClient` methods, the matching 33-method
  `AsyncInferenceClient`, 27 remote-facing methods across `Sandbox`,
  `SandboxPool`, `SandboxFiles`, and `SandboxProcess`, 17 `HfFileSystem`
  methods, three `CommitScheduler` controls, and the official CLI workflows.

The inventory includes official OpenAPI operations that do not yet have a
Python client method. It does not claim coverage of private, undocumented Hub
endpoints or arbitrary APIs implemented by user-owned Spaces.

## Disposition Legend

Every official capability receives exactly one disposition:

| Code | Disposition   | Meaning                                                                       |
| ---- | ------------- | ----------------------------------------------------------------------------- |
| `W`  | window        | A reusable, narrowly scoped read or protocol grant is appropriate.            |
| `E`  | execution     | Each exact mutation is an immutable Agent Operation.                          |
| `X`  | explicit-only | The operation cannot match broad family globs or fallback rules.              |
| `S`  | sealed        | Input or output includes a secret and uses the sealed payload store.          |
| `I`  | internal      | Broker plumbing may use it, but it is never an agent-facing tool.             |
| `O`  | operator-only | Credential/bootstrap configuration is available only to the trusted operator. |
| `L`  | local helper  | No distinct remote capability exists; map it to underlying operations.        |

Codes combine. For example, `E/X/S` is a one-use, explicit-only operation with
sealed secret handling.

Registration makes an operation available for policy evaluation. It does not
allow it. No-match remains deny. `X` operations require an exact operation name
in the matched rule.

## Canonical Broker Operations

### Identity, Discovery, and Public Catalogs

| Broker operation             | Disposition | Official capability                                                                    |
| ---------------------------- | ----------- | -------------------------------------------------------------------------------------- |
| `identity.read`              | `W`         | `whoami` and authenticated identity metadata.                                          |
| `auth.permission.check`      | `W`         | `auth_check` for an exact namespace/resource and permission set.                       |
| `catalog.model.list`         | `W`         | List/search models and model tags.                                                     |
| `catalog.dataset.list`       | `W`         | List/search datasets and dataset tags.                                                 |
| `catalog.space.list`         | `W`         | List/search Spaces, hardware, templates, and ZeroGPU quota.                            |
| `catalog.kernel.read`        | `W`         | List and inspect kernels.                                                              |
| `catalog.paper.list`         | `W`         | List, search, inspect, and read papers and Daily Papers.                               |
| `catalog.docs.search`        | `W`         | List and search Hugging Face documentation.                                            |
| `catalog.quicksearch`        | `W`         | Hub quick search.                                                                      |
| `catalog.agent_harness.list` | `W`         | List published agent harnesses.                                                        |
| `user.overview.read`         | `W`         | User profile, socials, avatar, followers, and following.                               |
| `organization.overview.read` | `W`         | Organization profile, socials, avatar, followers, and members.                         |
| `user.likes.read`            | `W`         | Liked repositories and repository likers.                                              |
| `user.repo.unlike`           | `E`         | Remove an existing repository like. The official client does not allow scripted likes. |

### Repository Metadata and Content Reads

These operations apply to models, datasets, and Spaces unless the provider API
limits the resource kind.

| Broker operation           | Disposition | Official capability                                       |
| -------------------------- | ----------- | --------------------------------------------------------- |
| `repo.list`                | `W`         | List user or organization repositories and storage usage. |
| `repo.metadata.read`       | `W`         | Model, dataset, Space, or generic repository info.        |
| `repo.exists`              | `W`         | Repository existence.                                     |
| `repo.revision.exists`     | `W`         | Revision existence.                                       |
| `repo.file.exists`         | `W`         | File existence.                                           |
| `repo.file.metadata.read`  | `W`         | File metadata and path info.                              |
| `repo.contents.read`       | `W`         | File resolve/download and bounded content reads.          |
| `repo.snapshot.read`       | `W`         | Bounded snapshot download.                                |
| `repo.tree.list`           | `W`         | Repository tree, files, and folder sizes.                 |
| `repo.refs.list`           | `W`         | Branches, tags, and conversion refs.                      |
| `repo.commits.list`        | `W`         | Commit history and compare metadata.                      |
| `repo.lfs.list`            | `W`         | LFS/Xet file inventory.                                   |
| `repo.checksums.verify`    | `W`         | Verify repository checksums.                              |
| `repo.security.read`       | `W`         | Model, dataset, or Space security scan status.            |
| `repo.notebook.read`       | `W`         | Notebook rendering URL.                                   |
| `dataset.parquet.list`     | `W`         | Dataset parquet conversion files.                         |
| `dataset.leaderboard.read` | `W`         | Dataset leaderboard.                                      |

Credential-vending reads such as repository JWTs and Xet read/write tokens are
not part of these responses. They are internal protocol plumbing described
later.

### Git and Repository Content Mutations

| Broker operation            | Disposition | Official capability                                                    |
| --------------------------- | ----------- | ---------------------------------------------------------------------- |
| `git.fetch`                 | `W`         | Git upload-pack.                                                       |
| `git.push.append`           | `W`         | Classified fast-forward or append-only receive-pack.                   |
| `git.push.force`            | `W/X`       | Exact non-fast-forward receive-pack protocol window.                   |
| `git.ref.delete`            | `W/X`       | Exact receive-pack ref-deletion protocol window.                       |
| `git.tag.update`            | `W/X`       | Exact receive-pack tag-rewrite protocol window.                        |
| `repo.commit.create`        | `E`         | HTTP commit with an exact file operation manifest and content digests. |
| `repo.file.upload`          | `E`         | Upload file/folder/large folder as a canonical commit plan.            |
| `repo.file.copy`            | `E`         | Server-side copy within or across repositories/buckets.                |
| `repo.file.delete`          | `E/X`       | Delete exact files or folder paths through a commit.                   |
| `repo.branch.create`        | `E`         | Create an exact branch from an observed revision.                      |
| `repo.branch.delete`        | `E/X`       | Delete an exact non-default branch.                                    |
| `repo.tag.create`           | `E`         | Create an exact tag at an observed revision.                           |
| `repo.tag.delete`           | `E/X`       | Delete an exact tag.                                                   |
| `repo.history.super_squash` | `E/X`       | Destructively squash a ref's history.                                  |
| `repo.lfs.permanent_delete` | `E/X`       | Permanently delete exact LFS objects.                                  |

Preupload negotiation, LFS duplication, Xet tokens, upload URLs, and commit
transport calls are internal steps of the approved plan, not separate tools.

### Repository Administration

| Broker operation          | Disposition | Official capability                                                                                                |
| ------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------ |
| `repo.create`             | `E/X`       | Create model, dataset, Space, or kernel with exact visibility, region, resource group, and kind-specific settings. |
| `repo.duplicate`          | `E`         | Duplicate a repository to an exact destination and configuration.                                                  |
| `repo.delete`             | `E/X`       | Irreversibly delete an exact repository.                                                                           |
| `repo.move`               | `E/X`       | Rename or transfer an exact repository.                                                                            |
| `repo.visibility.update`  | `E`         | Set public, private, or protected visibility where supported.                                                      |
| `repo.gating.update`      | `E`         | Set gated access to automatic, manual, or disabled.                                                                |
| `repo.resource_group.set` | `E/X`       | Move an exact repository into an organization resource group.                                                      |

`repo.settings.update` is not a catch-all operation. The adapter splits the
upstream settings endpoint into the exact setting operations above.

### Gated Repository Access

| Broker operation             | Disposition | Official capability                                |
| ---------------------------- | ----------- | -------------------------------------------------- |
| `repo.access.request.create` | `E`         | Ask for access to an exact gated repository.       |
| `repo.access.request.cancel` | `E`         | Cancel the requester's exact pending request.      |
| `repo.access.request.list`   | `W`         | List pending, accepted, or rejected requests.      |
| `repo.access.report.export`  | `W/X`       | Export the repository user-access report.          |
| `repo.access.request.accept` | `E/X`       | Accept one exact request.                          |
| `repo.access.request.reject` | `E/X`       | Reject one exact request.                          |
| `repo.access.grant`          | `E/X`       | Grant access to one exact user.                    |
| `repo.access.request.batch`  | `E/X`       | Apply one exact bounded batch of access decisions. |

### Discussions, Pull Requests, Posts, and Comments

| Broker operation            | Disposition | Official capability                                                   |
| --------------------------- | ----------- | --------------------------------------------------------------------- |
| `discussion.list`           | `W`         | List repository discussions and pull requests.                        |
| `discussion.read`           | `W`         | Read discussion details.                                              |
| `discussion.create`         | `E`         | Create a repository discussion.                                       |
| `discussion.delete`         | `E/X`       | Delete an exact discussion or post.                                   |
| `discussion.comment.create` | `E`         | Comment or reply on a repo discussion, blog, paper, or post.          |
| `discussion.comment.edit`   | `E`         | Edit an exact comment.                                                |
| `discussion.comment.hide`   | `E/X`       | Hide an exact comment.                                                |
| `discussion.title.update`   | `E`         | Rename a discussion.                                                  |
| `discussion.status.update`  | `E`         | Open or close a discussion.                                           |
| `discussion.pin.update`     | `E`         | Pin or unpin a discussion.                                            |
| `pull_request.create`       | `E`         | Create a pull request with an exact title, body, and source revision. |
| `pull_request.merge`        | `E/X`       | Merge an exact observed pull request head.                            |
| `pull_request.ref.delete`   | `E/X`       | Delete an exact pull request ref.                                     |
| `pull_request.storage.read` | `W`         | Read pull request storage estimate.                                   |

### Space Runtime and Configuration

| Broker operation          | Disposition | Official capability                                                  |
| ------------------------- | ----------- | -------------------------------------------------------------------- |
| `space.runtime.read`      | `W`         | Runtime state and bounded wait.                                      |
| `space.logs.read`         | `W`         | Bounded/followed build or container logs.                            |
| `space.events.read`       | `W`         | Bounded runtime event stream.                                        |
| `space.metrics.read`      | `W`         | Bounded runtime metrics stream.                                      |
| `space.restart`           | `E`         | Restart the exact observed runtime generation.                       |
| `space.pause`             | `E`         | Pause the exact observed runtime.                                    |
| `space.hardware.update`   | `E/X`       | Request exact hardware and sleep settings with cost presentation.    |
| `space.sleep_time.update` | `E`         | Set exact inactivity sleep time.                                     |
| `space.dev_mode.enable`   | `E/X`       | Enable development mode.                                             |
| `space.dev_mode.disable`  | `E/X`       | Disable development mode.                                            |
| `space.hot_reload.apply`  | `E/X`       | Apply an exact digest-bound hot-reload manifest in development mode. |
| `space.hot_reload.read`   | `W/X`       | Read bounded hot-reload status and events.                           |
| `space.variable.list`     | `W`         | List variables.                                                      |
| `space.variable.set`      | `E`         | Upsert an exact variable and description.                            |
| `space.variable.delete`   | `E`         | Delete an exact variable.                                            |
| `space.secret.list`       | `W`         | List secret names and metadata, never values.                        |
| `space.secret.set`        | `E/X/S`     | Upsert an exact write-only secret.                                   |
| `space.secret.delete`     | `E/X`       | Delete an exact secret.                                              |
| `space.volume.set`        | `E/X`       | Replace the exact mounted-volume set.                                |
| `space.volume.delete`     | `E/X`       | Delete all mounted volumes.                                          |

Deprecated Space storage methods map to volume operations. `duplicate_space`
maps to `repo.duplicate`. A separate `space.resume` operation is not listed
because the pinned official client exposes pause and restart, not a stable
resume call; restart is not silently renamed to resume.

### Buckets and Objects

| Broker operation            | Disposition | Official capability                                                |
| --------------------------- | ----------- | ------------------------------------------------------------------ |
| `bucket.list`               | `W`         | List namespace buckets.                                            |
| `bucket.metadata.read`      | `W`         | Bucket details.                                                    |
| `bucket.create`             | `E`         | Create a bucket with exact visibility, region, and resource group. |
| `bucket.delete`             | `E/X`       | Irreversibly delete an exact bucket.                               |
| `bucket.move`               | `E/X`       | Rename or transfer an exact bucket.                                |
| `bucket.visibility.update`  | `E`         | Update exact bucket visibility.                                    |
| `bucket.resource_group.set` | `E/X`       | Move an exact bucket into a resource group.                        |
| `bucket.object.list`        | `W`         | List bounded tree/path metadata.                                   |
| `bucket.object.read`        | `W`         | Read metadata or bounded object content.                           |
| `bucket.object.write`       | `W`         | Add exact objects under a scoped reusable grant.                   |
| `bucket.object.copy`        | `E`         | Copy exact objects within/across buckets and repos.                |
| `bucket.object.delete`      | `E/X`       | Delete exact objects.                                              |
| `bucket.batch.apply`        | `E`         | Apply a bounded canonical add/copy/delete manifest.                |
| `bucket.sync.apply`         | `E`         | Apply a previously generated, digest-bound sync plan.              |

Local sync planning and downloads map to list/read operations. `sync_job_volume`
maps to bucket creation/object writes plus the consuming Job plan.

### Collections

| Broker operation                | Disposition | Official capability                                                    |
| ------------------------------- | ----------- | ---------------------------------------------------------------------- |
| `collection.list`               | `W`         | List and inspect collections.                                          |
| `collection.create`             | `E`         | Create an exact collection.                                            |
| `collection.metadata.update`    | `E`         | Update title, description, theme, or visibility through closed fields. |
| `collection.delete`             | `E/X`       | Delete an exact collection.                                            |
| `collection.item.add`           | `E`         | Add an exact item.                                                     |
| `collection.item.update`        | `E`         | Update item note or position.                                          |
| `collection.item.delete`        | `E`         | Delete an exact item.                                                  |
| `collection.item.batch`         | `E`         | Apply a bounded exact item update batch.                               |
| `collection.resource_group.set` | `E/X`       | Assign an exact collection to a resource group.                        |

### Webhooks

| Broker operation          | Disposition | Official capability                                                            |
| ------------------------- | ----------- | ------------------------------------------------------------------------------ |
| `webhook.list`            | `W`         | List and inspect webhooks with secrets redacted.                               |
| `webhook.create`          | `E/X/S`     | Create an exact webhook, watched resources, domains, URL, and optional secret. |
| `webhook.update`          | `E/X/S`     | Update closed webhook fields and optional sealed secret.                       |
| `webhook.enable`          | `E`         | Enable an exact webhook.                                                       |
| `webhook.disable`         | `E`         | Disable an exact webhook.                                                      |
| `webhook.delete`          | `E/X`       | Delete an exact webhook.                                                       |
| `webhook.delivery.replay` | `E/X`       | Replay one exact delivery log entry.                                           |

### Jobs and Scheduled Jobs

| Broker operation                | Disposition | Official capability                                                                                         |
| ------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------- |
| `job.hardware.list`             | `W`         | List Job hardware and pricing metadata.                                                                     |
| `job.list`                      | `W`         | List/count Jobs.                                                                                            |
| `job.read`                      | `W`         | Inspect/wait for a Job.                                                                                     |
| `job.logs.read`                 | `W`         | Read/follow bounded Job logs and events.                                                                    |
| `job.metrics.read`              | `W`         | Read bounded Job metrics.                                                                                   |
| `job.run`                       | `E/X/S`     | Run an exact image digest, argv, resources, volumes, environment, secrets, ports, timeout, and SSH setting. |
| `job.uv.run`                    | `E/X/S`     | Run an exact script/content digest, dependencies, Python version, and Job configuration.                    |
| `job.duplicate`                 | `E/X/S`     | Duplicate an observed Job into an exact new plan.                                                           |
| `job.cancel`                    | `E`         | Cancel an exact active Job.                                                                                 |
| `job.labels.update`             | `E`         | Replace exact Job labels.                                                                                   |
| `scheduled_job.list`            | `W`         | List and inspect scheduled Jobs.                                                                            |
| `scheduled_job.create`          | `E/X/S`     | Create an exact scheduled Job and schedule.                                                                 |
| `scheduled_job.uv.create`       | `E/X/S`     | Create an exact scheduled UV Job.                                                                           |
| `scheduled_job.delete`          | `E/X`       | Delete an exact scheduled Job.                                                                              |
| `scheduled_job.suspend`         | `E`         | Suspend an exact scheduled Job.                                                                             |
| `scheduled_job.resume`          | `E`         | Resume an exact scheduled Job.                                                                              |
| `scheduled_job.trigger`         | `E/X`       | Trigger one immediate run.                                                                                  |
| `scheduled_job.schedule.update` | `E/X`       | Change the exact schedule/concurrency settings.                                                             |
| `scheduled_job.labels.update`   | `E`         | Replace exact scheduled Job labels.                                                                         |

Arbitrary Job commands remain available, but only as exact, digest-bound plans.
Secrets are sealed and cost/resource settings are prominent in approval text.
The broker never returns raw SSH credentials to an agent.

### Sandboxes

The official Sandbox API is a managed workflow over Jobs plus a sandbox server.
Its dynamic command and file APIs are still typed broker operations. The
approved plan binds the backing Job configuration, sandbox identity, argv or
shell string, file paths, content digests, environment, timeout, and output
limits.

| Broker operation       | Disposition | Official capability                                                                               |
| ---------------------- | ----------- | ------------------------------------------------------------------------------------------------- |
| `sandbox.create`       | `E/X/S`     | Create an exact sandbox Job, image, resources, environment, secrets, lifetime, and exposed ports. |
| `sandbox.connect`      | `W/X`       | Attach broker plumbing to an exact existing sandbox.                                              |
| `sandbox.read`         | `W/X`       | Read exact sandbox image, host, and lifecycle metadata.                                           |
| `sandbox.delete`       | `E/X`       | Close a sandbox and cancel its backing Job.                                                       |
| `sandbox.command.run`  | `E/X`       | Run exact argv with bounded output; shell mode is a separate explicit plan attribute.             |
| `sandbox.process.list` | `W/X`       | List processes in an exact sandbox.                                                               |
| `sandbox.process.kill` | `E/X`       | Kill one exact observed process.                                                                  |
| `sandbox.file.list`    | `W/X`       | List/stat/exists under exact bounded sandbox paths.                                               |
| `sandbox.file.read`    | `W/X`       | Read/download exact bounded sandbox files.                                                        |
| `sandbox.file.write`   | `E/X`       | Write/upload exact paths with content digests and modes.                                          |
| `sandbox.file.mkdir`   | `E/X`       | Create an exact directory and mode.                                                               |
| `sandbox.file.delete`  | `E/X`       | Delete an exact path with explicit recursive intent.                                              |
| `sandbox.port.proxy`   | `W/X/I`     | Broker-proxied access to an exact port/path; derived proxy credentials never leave the broker.    |
| `sandbox.pool.create`  | `E/X`       | Create an exact paid host-pool configuration.                                                     |
| `sandbox.pool.connect` | `W/X`       | Attach to an exact existing pool.                                                                 |
| `sandbox.pool.read`    | `W/X`       | Read host/sandbox counts and IDs.                                                                 |
| `sandbox.pool.warm`    | `E/X`       | Warm an exact bounded number of hosts with cost presentation.                                     |
| `sandbox.pool.delete`  | `E/X`       | Close the pool and cancel its exact backing hosts.                                                |

The CLI's interactive Sandbox shell, Job SSH, and Space SSH are not raw-token
tools. BrokerKit may provide a bounded proxied session only through a dedicated
session operation that keeps derived credentials inside the broker. Until that
session adapter exists, these workflows are operator-only rather than mapped to
`sandbox.command.run` implicitly.

Agent-created sandboxes must never receive the broker's root HF token through
`forward_hf_token`. A future credential mount must select a separately scoped
and revocable credential, bind its destination and lifetime to the plan, inject
it through the sealed path, and revoke it at terminal state. Until that exists,
token forwarding is operator-only.

### Inference Endpoints

| Broker operation          | Disposition | Official capability                                                                        |
| ------------------------- | ----------- | ------------------------------------------------------------------------------------------ |
| `endpoint.catalog.list`   | `W`         | List Inference Endpoint catalog models.                                                    |
| `endpoint.list`           | `W`         | List endpoints in an exact namespace.                                                      |
| `endpoint.read`           | `W`         | Inspect one endpoint.                                                                      |
| `endpoint.create`         | `E/X/S`     | Deploy an exact model/image, compute, scaling, networking, environment, secrets, and tags. |
| `endpoint.catalog.create` | `E/X`       | Deploy an exact catalog model using resolved defaults.                                     |
| `endpoint.update`         | `E/X/S`     | Apply a closed, exact endpoint configuration update.                                       |
| `endpoint.pause`          | `E`         | Pause an exact endpoint.                                                                   |
| `endpoint.resume`         | `E/X`       | Resume an exact endpoint with cost presentation.                                           |
| `endpoint.scale_to_zero`  | `E`         | Scale an exact endpoint to zero.                                                           |
| `endpoint.delete`         | `E/X`       | Delete an exact endpoint.                                                                  |

### Inference Calls

Each task has its own closed request and response schema. Do not expose one
untyped `inference.invoke` body.

| Broker operation family | Disposition | Exact operations                                                                                                                                                                                                                                                                                                                                         |
| ----------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Text                    | `W`         | `inference.chat.complete`, `inference.text.generate`, `inference.text.classify`, `inference.text.summarize`, `inference.text.translate`, `inference.token.classify`, `inference.fill_mask`, `inference.question_answer`, `inference.table_question_answer`, `inference.zero_shot.classify`, `inference.sentence_similarity`, `inference.feature.extract` |
| Audio                   | `W`         | `inference.audio.classify`, `inference.audio.transform`, `inference.audio.transcribe`, `inference.text_to_speech`                                                                                                                                                                                                                                        |
| Image                   | `W`         | `inference.image.classify`, `inference.image.segment`, `inference.image.transform`, `inference.image.caption`, `inference.document_question_answer`, `inference.text_to_image`, `inference.object.detect`, `inference.visual_question_answer`, `inference.zero_shot.image_classify`                                                                      |
| Video                   | `W`         | `inference.image_to_video`, `inference.text_to_video`                                                                                                                                                                                                                                                                                                    |
| Tabular                 | `W`         | `inference.tabular.classify`, `inference.tabular.regress`                                                                                                                                                                                                                                                                                                |
| Endpoint metadata       | `W`         | `inference.models.list`, `inference.endpoint.info`, `inference.endpoint.health`                                                                                                                                                                                                                                                                           |

`InferenceClient.chat` is a facade and `chat_completion` is the canonical call;
both map to `inference.chat.complete`. Client `close` is a local helper.

### Organization and Enterprise Administration

These operations use separate exact organization and resource-group targets.
Enterprise-only operations are still registered when the pinned API is stable;
an upstream plan/license error is not treated as an unknown operation.

| Broker operation                       | Disposition | Official capability                                                           |
| -------------------------------------- | ----------- | ----------------------------------------------------------------------------- |
| `organization.repositories.list`       | `W`         | Organization repository/storage inventory.                                    |
| `organization.audit.export`            | `W/X`       | Export a bounded audit-log interval.                                          |
| `organization.billing.read`            | `W/X`       | Usage, resource-group usage, inference-session usage, and bounded live usage. |
| `organization.network_security.read`   | `W/X`       | Read network security configuration.                                          |
| `organization.network_security.update` | `E/X`       | Apply an exact closed network-security configuration.                         |
| `organization.member.list`             | `W`         | List members.                                                                 |
| `organization.member.role.update`      | `E/X`       | Change one exact member role.                                                 |
| `organization.member.token.revoke`     | `E/X`       | Revoke one exact member token.                                                |
| `resource_group.list`                  | `W`         | List and inspect resource groups.                                             |
| `resource_group.create`                | `E/X`       | Create an exact resource group.                                               |
| `resource_group.update`                | `E/X`       | Update exact name/description settings.                                       |
| `resource_group.delete`                | `E/X`       | Delete an exact empty/eligible resource group.                                |
| `resource_group.auto_join.update`      | `E/X`       | Configure exact auto-join settings.                                           |
| `resource_group.member.add`            | `E/X`       | Add exact users.                                                              |
| `resource_group.member.remove`         | `E/X`       | Remove one exact user.                                                        |
| `resource_group.member.role.update`    | `E/X`       | Change one exact resource-group role.                                         |
| `service_account.list`                 | `W/X`       | List and inspect service accounts.                                            |
| `service_account.create`               | `E/X`       | Create an exact service account.                                              |
| `service_account.delete`               | `E/X`       | Delete an exact service account.                                              |
| `service_account.token.create`         | `E/X/S`     | Create a token directly into a sealed broker credential slot.                 |
| `service_account.token.update`         | `E/X`       | Update exact token metadata/permissions.                                      |
| `service_account.token.rotate`         | `E/X/S`     | Rotate directly into a sealed broker credential slot.                         |
| `service_account.token.delete`         | `E/X`       | Delete an exact token.                                                        |

Service-account token plaintext is never returned to the requesting agent or
operator inbox. The plan names the destination broker credential slot.

### SCIM

SCIM uses a distinct credential realm and standards-compliant schemas. Every
mutation remains exact and explicit-only.

| Broker operation         | Disposition | Official capability                                          |
| ------------------------ | ----------- | ------------------------------------------------------------ |
| `scim.capabilities.read` | `W/X`       | Service provider configuration, resource types, and schemas. |
| `scim.user.list`         | `W/X`       | List and inspect SCIM users.                                 |
| `scim.user.create`       | `E/X`       | Create/invite an exact SCIM user.                            |
| `scim.user.replace`      | `E/X`       | PUT an exact complete SCIM user representation.              |
| `scim.user.patch`        | `E/X`       | Apply a closed bounded SCIM PatchOp.                         |
| `scim.user.delete`       | `E/X`       | Delete/deprovision an exact SCIM user.                       |
| `scim.group.list`        | `W/X`       | List and inspect SCIM groups.                                |
| `scim.group.create`      | `E/X`       | Create an exact SCIM group.                                  |
| `scim.group.replace`     | `E/X`       | PUT an exact complete group representation.                  |
| `scim.group.patch`       | `E/X`       | Apply a closed bounded group PatchOp.                        |
| `scim.group.delete`      | `E/X`       | Delete an exact SCIM group.                                  |

Both `/scim/v2` and `/scim-provisioning/v2` routes map to the same operation
vocabulary with a descriptor-selected API flavor. The flavor is part of the
immutable plan.

### User Settings and Notifications

| Broker operation                  | Disposition | Official capability                                                      |
| --------------------------------- | ----------- | ------------------------------------------------------------------------ |
| `user.billing.read`               | `W/X`       | User usage, Jobs usage, inference-session usage, and bounded live usage. |
| `notification.list`               | `W`         | List notifications.                                                      |
| `notification.delete`             | `E`         | Delete exact/all notifications as explicitly requested.                  |
| `notification.read_status.update` | `E`         | Mark an exact bounded set read/unread.                                   |
| `notification.settings.update`    | `E`         | Apply a closed notification settings update.                             |
| `watch.settings.update`           | `E`         | Apply an exact watch setting.                                            |
| `user.mcp_tools.read`             | `W`         | Read the authenticated user's Hub MCP tool configuration.                |

### Papers and SQL Console Embeds

| Broker operation         | Disposition | Official capability                  |
| ------------------------ | ----------- | ------------------------------------ |
| `paper.authorship.claim` | `E/X`       | Claim authorship of an exact paper.  |
| `paper.index`            | `E/X`       | Request indexing for an exact paper. |
| `paper.links.update`     | `E/X`       | Update exact paper links.            |
| `sql_embed.create`       | `E/X`       | Create an exact SQL Console embed.   |
| `sql_embed.update`       | `E/X`       | Update an exact embed.               |
| `sql_embed.delete`       | `E/X`       | Delete an exact embed.               |

Paper/blog/post comments use `discussion.comment.create`.

### Agentic Provisioning

The live OpenAPI exposes this family. It is preview-like and credential-heavy,
but it is not omitted from the inventory.

| Broker operation                           | Disposition | Official capability                                |
| ------------------------------------------ | ----------- | -------------------------------------------------- |
| `provisioning.service.list`                | `W/X`       | Health and service catalog.                        |
| `provisioning.account.request`             | `E/X`       | Create an exact account request.                   |
| `provisioning.resource.create`             | `E/X/S`     | Provision an exact service/resource configuration. |
| `provisioning.resource.read`               | `W/X`       | Inspect an exact provisioned resource.             |
| `provisioning.resource.service.update`     | `E/X/S`     | Change the exact backing service.                  |
| `provisioning.resource.remove`             | `E/X`       | Remove an exact resource.                          |
| `provisioning.resource.credentials.rotate` | `E/X/S`     | Rotate credentials into a sealed broker slot.      |
| `provisioning.deep_link.create`            | `E/X`       | Create an exact short-lived deep link.             |

The provider descriptor pins the upstream schema revision. Schema drift fails
closed until reviewed; it never falls back to arbitrary JSON forwarding.

## Internal and Operator-Only Capabilities

These official endpoints are accounted for but deliberately are not exposed as
agent tools.

| Capability                                                                   | Disposition    | Rule                                                                                              |
| ---------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------- |
| Repository JWT generation                                                    | `I`            | Consume only inside the exact protocol adapter; never return the JWT.                             |
| Xet read/write token generation                                              | `I`            | Consume only for approved repository/bucket transfer.                                             |
| Container registry token                                                     | `I`            | Consume only inside an exact registry operation; never return it.                                 |
| LFS/Xet preupload and duplicate                                              | `I`            | Internal steps of commit/bucket plans.                                                            |
| OAuth device authorization                                                   | `O/S`          | Trusted operator credential bootstrap only.                                                       |
| OAuth dynamic client registration                                            | `O/X/S`        | Trusted installation administration only.                                                         |
| OAuth userinfo                                                               | `O`            | Credential bootstrap validation; normal identity reads use `identity.read`.                       |
| OIDC token detection, exchange, and login                                    | `O/S`          | Trusted workload/operator bootstrap; exchanged tokens enter a sealed credential slot.             |
| Sandbox and SSH proxy credentials                                            | `I`            | Used only by a broker-owned bounded proxy/session adapter.                                        |
| Sandbox `forward_hf_token` using the broker credential                       | `O/S`          | Forbidden for agent operations; operator-only until scoped, revocable credential mounts exist.    |
| Local cache, checksum parser, URL builder, future executor, and client close | `L`            | No remote operation.                                                                              |
| Space application-specific HTTP/Gradio API                                   | `O` by default | May be enabled only through an operator-installed, versioned schema adapter for that exact Space. |

Approval does not make credential exfiltration safe. Any future use case that
needs a short-lived credential must consume it inside BrokerKit or place it into
a sealed credential slot; it must not add a `token.get` operation.

## Official `HfApi` Coverage Ledger

All 161 public methods at the pinned commit are accounted for below. Aliases,
composed workflows, and local helpers map to canonical operations rather than
creating duplicate policy names.

| Group                         | Official methods                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Canonical treatment                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Identity and discovery        | `whoami`, `auth_check`, `get_model_tags`, `get_dataset_tags`, `list_models`, `list_datasets`, `list_spaces`, `search_spaces`, `list_user_repos`, `get_user_overview`, `get_organization_overview`, `list_organization_followers`, `list_organization_members`, `list_user_followers`, `list_user_following`, `list_liked_repos`, `list_repo_likers`, `unlike`, `list_papers`, `list_daily_papers`, `paper_info`, `read_paper`, `kernel_info`                                  | Identity/catalog/user operations.                                        |
| Repository reads              | `model_info`, `dataset_info`, `space_info`, `repo_info`, `repo_exists`, `revision_exists`, `file_exists`, `list_repo_files`, `list_repo_tree`, `list_repo_refs`, `list_repo_commits`, `get_paths_info`, `get_hf_file_metadata`, `hf_hub_download`, `snapshot_download`, `get_safetensors_metadata`, `verify_repo_checksums`, `list_lfs_files`, `get_dataset_leaderboard`, `list_dataset_parquet_files`, `list_space_templates`                                                | Typed repository/catalog reads.                                          |
| Repository administration     | `create_repo`, `delete_repo`, `duplicate_repo`, `move_repo`, `update_repo_settings`, `super_squash_history`, `permanently_delete_lfs_files`                                                                                                                                                                                                                                                                                                                                   | Exact administrative operations.                                         |
| Repository writes             | `create_commit`, `upload_file`, `upload_folder`, `upload_large_folder`, `delete_file`, `delete_files`, `delete_folder`, `copy_files`, `create_branch`, `delete_branch`, `create_tag`, `delete_tag`, `preupload_lfs_files`                                                                                                                                                                                                                                                     | Canonical commit/ref operations; preupload is internal.                  |
| Discussions and pull requests | `get_repo_discussions`, `get_discussion_details`, `create_discussion`, `create_pull_request`, `comment_discussion`, `rename_discussion`, `change_discussion_status`, `merge_pull_request`, `edit_discussion_comment`, `hide_discussion_comment`                                                                                                                                                                                                                               | Discussion and pull-request operations.                                  |
| Gated access                  | `list_pending_access_requests`, `list_accepted_access_requests`, `list_rejected_access_requests`, `cancel_access_request`, `accept_access_request`, `reject_access_request`, `grant_access`                                                                                                                                                                                                                                                                                   | Repository access operations.                                            |
| Space                         | `get_space_runtime`, `get_space_secrets`, `get_space_variables`, `add_space_secret`, `delete_space_secret`, `add_space_variable`, `delete_space_variable`, `list_spaces_hardware`, `request_space_hardware`, `set_space_sleep_time`, `pause_space`, `restart_space`, `enable_space_dev_mode`, `disable_space_dev_mode`, `fetch_space_logs`, `wait_for_space`, `set_space_volumes`, `delete_space_volumes`, `request_space_storage`, `delete_space_storage`, `duplicate_space` | Space operations; deprecated methods map to volume/duplicate operations. |
| Inference Endpoints           | `list_inference_catalog`, `list_inference_endpoints`, `get_inference_endpoint`, `create_inference_endpoint`, `create_inference_endpoint_from_catalog`, `update_inference_endpoint`, `delete_inference_endpoint`, `pause_inference_endpoint`, `resume_inference_endpoint`, `scale_to_zero_inference_endpoint`                                                                                                                                                                  | Endpoint operations.                                                     |
| Collections                   | `list_collections`, `get_collection`, `create_collection`, `update_collection_metadata`, `delete_collection`, `add_collection_item`, `update_collection_item`, `delete_collection_item`                                                                                                                                                                                                                                                                                       | Collection operations.                                                   |
| Webhooks                      | `list_webhooks`, `get_webhook`, `create_webhook`, `update_webhook`, `enable_webhook`, `disable_webhook`, `delete_webhook`                                                                                                                                                                                                                                                                                                                                                     | Webhook operations.                                                      |
| Jobs                          | `list_jobs_hardware`, `list_jobs`, `inspect_job`, `wait_for_job`, `fetch_job_logs`, `fetch_job_metrics`, `run_job`, `run_uv_job`, `cancel_job`, `update_job_labels`, `create_scheduled_job`, `create_scheduled_uv_job`, `list_scheduled_jobs`, `inspect_scheduled_job`, `delete_scheduled_job`, `suspend_scheduled_job`, `resume_scheduled_job`, `trigger_scheduled_job`, `update_scheduled_job_labels`, `sync_job_volume`                                                    | Job/scheduled-Job operations; volume sync composes bucket operations.    |
| Buckets                       | `create_bucket`, `bucket_info`, `list_buckets`, `delete_bucket`, `move_bucket`, `list_bucket_tree`, `get_bucket_paths_info`, `get_bucket_file_metadata`, `download_bucket_files`, `batch_bucket_files`, `sync_bucket`                                                                                                                                                                                                                                                         | Bucket operations.                                                       |
| Local/composed helpers        | `run_as_future`, `get_full_repo_name`, `parse_safetensors_file_metadata`                                                                                                                                                                                                                                                                                                                                                                                                      | Local helper or composition over identity/read operations.               |

## Official `InferenceClient` Coverage Ledger

All 33 public methods are accounted for:

- text: `chat`, `chat_completion`, `feature_extraction`, `fill_mask`,
  `question_answering`, `sentence_similarity`, `summarization`,
  `table_question_answering`, `text_classification`, `text_generation`,
  `token_classification`, `translation`, `zero_shot_classification`;
- audio: `audio_classification`, `audio_to_audio`,
  `automatic_speech_recognition`, `text_to_speech`;
- image/video: `document_question_answering`, `image_classification`,
  `image_segmentation`, `image_to_image`, `image_to_text`, `image_to_video`,
  `object_detection`, `text_to_image`, `text_to_video`,
  `visual_question_answering`,
  `zero_shot_image_classification`;
- tabular: `tabular_classification`, `tabular_regression`;
- endpoint metadata: `get_endpoint_info`, `health_check`;
- local helper: `close`.

The generated Python type directory contains provider/task models beyond this
public client surface. Add them only when they become a stable public method or
live OpenAPI operation; do not infer operations from generated types alone.

`AsyncInferenceClient` exposes the same 33 method names and maps to the same
operations. It is a transport style, not a second capability family.

## Official Workflow Client Coverage Ledger

| Official surface  | Public methods/workflows                                                                                                                                                                  | Canonical treatment                                                                                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Sandbox`         | `create`, `connect`, `close`, `run`, `processes`, `image`, `host_id`, `proxy_url_for`, `proxy_headers`                                                                                    | Sandbox lifecycle, command, process, metadata, and internal proxy operations.                                                                                         |
| `SandboxPool`     | `create`, `connect`, `close`, `warm`, `num_hosts`, `num_sandboxes`, `host_ids`                                                                                                            | Sandbox-pool operations.                                                                                                                                              |
| `SandboxFiles`    | `read`, `read_text`, `write`, `upload`, `download`, `list`, `stat`, `exists`, `delete`, `mkdir`                                                                                           | Sandbox file operations.                                                                                                                                              |
| `SandboxProcess`  | `kill`                                                                                                                                                                                    | `sandbox.process.kill`.                                                                                                                                               |
| `HfFileSystem`    | `cp_file`, `exists`, `find`, `get_file`, `glob`, `info`, `isdir`, `isfile`, `ls`, `modified`, `resolve_path`, `rm`, `start_transaction`, `transaction`, `url`, `walk`, `invalidate_cache` | Repository/bucket read, copy, delete, and commit operations; cache invalidation and transaction objects are local helpers.                                            |
| `CommitScheduler` | `push_to_hub`, `trigger`, `stop`                                                                                                                                                          | Repeated local composition over exact repository commit plans. Enabling a persistent schedule is operator-only until BrokerKit owns a durable typed schedule adapter. |
| Login/OIDC        | `login`, `logout`, `auth_switch`, `auth_list`, `interpreter_login`, `notebook_login`, `oidc_login`, `get_oidc_token`, `exchange_oidc_token`                                               | Local/operator-only credential bootstrap and sealed credential slots.                                                                                                 |
| Webhook server    | `webhook_endpoint` and OAuth callback helpers                                                                                                                                             | Inbound application framework helpers, not remote Hugging Face operations.                                                                                            |

The official CLI is checked as a workflow surface. Repository/filesystem,
bucket, collection, discussion, Space, Job, Endpoint, webhook, paper, download,
and upload commands map to the operations above. Auth, cache, extension, skill,
completion, and local system commands are local or operator-only. Space hot
reload maps to dev-mode plus exact file synchronization/reload operations;
interactive Space/Job/Sandbox SSH remains operator-only until the bounded
session adapter exists.

## OpenAPI-Only Coverage Ledger

The following live OpenAPI families are absent or incomplete in `HfApi` and are
still required by this inventory:

- repository resource-group assignment, access-report export, batched access
  decisions, security/notebook/JWT endpoints, and pull-request deletion,
  pinning, ref deletion, and storage estimates;
- Bucket settings/resource-group assignment and explicit batch primitives;
- Space events, metrics, volumes, ZeroGPU quota, and lower-level secret and
  variable routes;
- Job count/events/duplication and scheduled-Job schedule update;
- webhook delivery replay;
- organization roles, network security, audit exports, usage, and member-token
  revocation;
- resource-group lifecycle, membership, roles, and auto-join;
- service-account lifecycle and token lifecycle;
- SCIM and SCIM provisioning users/groups;
- user usage, notifications, watch settings, and MCP tool settings;
- paper claims/indexing/link updates and blog/paper/post comments;
- SQL Console embed lifecycle;
- agentic provisioning lifecycle;
- OAuth, repository/Xet/container token vending, docs/search, agent harnesses,
  and kernel reads, with the internal/operator dispositions above.

## Drift and Completion Gate

Implementation must add a checked-in machine-readable capability manifest
generated from the provider descriptor registry. CI compares it with:

1. the pinned live OpenAPI snapshot;
2. the pinned official `HfApi` public method list; and
3. the pinned sync and async Inference client method lists;
4. the pinned Sandbox, filesystem, scheduler, auth/OIDC, and CLI workflow
   surfaces.

Every added, removed, or changed upstream operation fails the drift check until
it receives an explicit mapping and disposition. A capability may be marked
`blocked-upstream` only with the exact official operation, observed blocker,
and issue/reference. It cannot be marked blocked merely because implementation
is unfinished.

The HF administrative cutover is not complete while any operation in this
inventory is unmapped, silently omitted, or reachable only through arbitrary
HTTP forwarding.
