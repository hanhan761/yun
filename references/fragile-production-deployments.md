# 脆弱生产服务器的安全同步与发布

Use this workflow for low-core, low-memory, small-disk, low-bandwidth, or
I/O-sensitive production hosts, and for any host with a history of deployment-
induced stalls. Follow the repository's `AGENTS.md`, deployment docs, and owned
scripts first; use this reference to tighten them, never to bypass them.

## Non-negotiable release model

1. Build, compile, transpile, package, and run heavy tests on the development
   machine or CI runner.
2. Publish one immutable artifact: preferably an OCI image pinned by digest;
   for static assets, use a versioned archive or directory plus checksums.
3. Let production only authenticate, fetch, verify, migrate when required,
   switch releases, and run health checks.
4. Keep secrets, databases, uploads, backups, and other server-owned state out
   of source synchronization and release artifacts.
5. Permit only one deployment, backup, migration, cleanup, or other I/O-heavy
   maintenance job at a time.
6. Retain the exact previous working release until the new release passes its
   observation window.

Do not make `git pull` plus an on-host Docker/Node build the normal deployment
path. CPU and memory limits alone do not protect a live service from BuildKit,
package extraction, log, or filesystem I/O starvation.

## Release safety gate and required response

Inspect the complete planned command chain and the deployment scripts it calls
before the first production mutation. On a protected, resource-constrained, or
previously deployment-stalled production target, reject the ordinary release
path if it contains any production-side runtime artifact build, including:

- `docker build`, `docker buildx build`, `docker compose build`, or
  `docker compose up --build`;
- a Compose service with `build:` when the selected command can invoke or fall
  back to that build instead of requiring a prebuilt image;
- Node/package-manager, compiler, bundler, or image-packaging work that creates
  the release artifact on production; or
- source synchronization or `git pull` followed by any of those steps.

A project-owned script, a name such as `safe-deploy`, a deployment lock, CPU or
memory limits on the client process, health polling, or previously successful
runs do not clear this gate. Repository instructions may impose stricter rules;
they do not make an I/O-unsafe production build safe. Do not execute an earlier
mutation in a rejected command chain and do not silently substitute a different
on-host builder.

When the gate rejects a release, respond with all of the following instead of a
bare refusal:

1. Identify the target fact that activated the gate and the exact unsafe step
   or script that was rejected.
2. Return the correct, repository-specific release path:
   development/CI build and test -> immutable artifact publication -> digest or
   checksum capture -> production preflight and lock -> verified fetch ->
   migration when required -> no-build activation -> layered health checks and
   observation -> retained rollback.
3. Name the narrow production command or script that performs no-build
   activation. If none exists, state that this is the missing prerequisite and
   identify the minimal deployment-script/Compose change needed; do not run the
   unsafe path as a workaround.
4. If the user's original deployment authority covers the correct path and all
   prerequisites already exist, continue with that path. Otherwise stop before
   production mutation and report the concrete missing artifact, digest,
   credential mechanism, migration decision, or no-build entry point.

Use this compact response shape, adapted to the actual repository rather than
copied mechanically:

```text
Rejected: <production-side build step> on <verified fragile target>
Reason: <specific memory/I/O/live-service risk or prior incident fact>
Correct release:
  1. Build/test <artifact> on <development machine or CI> from <revision>
  2. Publish <immutable image digest or versioned bundle + checksums>
  3. On production: preflight + lock, fetch/verify, migrate if required,
     activate with <project command> in no-build mode
  4. Verify origin -> ingress/proxy -> public endpoints; observe >= project
     window; retain <exact rollback release>
Missing prerequisite: <none, or exact item that must be added>
```

## Select the smallest release path

- **Static-only change:** build off-host, validate the generated site, create a
  versioned bundle and checksum manifest, upload to staging, then activate it
  atomically with the project-owned edge/static deployment script.
- **Application change:** build and test the image off-host, push it once,
  resolve its content digest, and make production pull that exact digest.
- **Database or configuration change:** preserve the application artifact path,
  add a reviewed migration/configuration phase, and prove backward compatibility
  or use an authorized maintenance window.
- **Cross-service change:** stage it explicitly. Separate artifact preparation,
  asset transfer, migration, and cutover so a failed phase cannot leave a mixed
  release.

Do not redeploy unaffected services. Do not run a full-stack release merely to
publish static files when the repository provides a narrower path.

## Prepare the release off-host

1. Identify the authoritative repository instructions and deployment scripts.
   Confirm the real target, topology, domains, persistent paths, and secret
   boundaries instead of reviving a legacy deployment path.
2. Record the exact source revision. If explicitly deploying uncommitted work,
   record a reproducible source-tree digest and state that exception; never mix
   an unknown working tree with a named commit.
3. Build for the target architecture. Run the change-specific tests and syntax
   checks before contacting production.
4. Produce a small release manifest containing only non-secret provenance:
   source revision, artifact digest/checksums, target architecture, migration
   revision when applicable, build time, and the previous release identifier.
5. Scan the artifact and manifest for secrets. Never bake populated `.env`
   files, credentials, private keys, uploads, database files, or backups into an
   image or static bundle.
6. Prefer a private registry for OCI images. Authenticate through the target's
   protected credential store or secret mechanism; never put registry tokens in
   command arguments or logs.

Build once and promote the same artifact. Never rebuild separately on
production because a rebuild can change dependencies and defeats rollback by
digest.

## Gate the deployment before any mutation

Use the registered target and `probe`, then collect one timestamped preflight:

- target identity, current release/image digest, and authoritative topology;
- current origin, proxy/ingress, and off-host public health;
- container/service health, restart counts, and recent fatal/OOM/I/O errors;
- free bytes and inodes on every affected filesystem;
- available memory, swap state, load, and CPU/memory/I/O pressure;
- active builds, deployments, migrations, backups, package upgrades, and
  cleanup jobs;
- the exact rollback artifact/configuration and any database compatibility
  constraint.

Acquire a target-local deployment lock atomically and hold it through cutover
and verification. Abort before changing state when:

- the current service is degraded for an unexplained reason;
- another heavy or mutating job is active;
- the filesystem is read-only, OOM is active/recent, or I/O pressure is already
  sustained;
- estimated peak disk usage cannot hold the incoming artifact, its temporary
  representation/unpacking, the previous working release, and a safety reserve;
- the rollback artifact, schema compatibility, or health endpoint is unknown.

Use project-defined capacity thresholds. If none exist, do not guess from the
artifact's compressed size alone: measure or conservatively estimate peak
expanded usage and leave at least the larger of 15% of the affected filesystem
or 2 GiB free after that peak. A project may require more.

## Stage, verify, and activate

1. Fetch only the declared immutable artifact into a staging location. Prefer
   registry pull by digest over copying Docker archives.
2. Verify every digest/checksum and the target architecture before activation.
3. Validate candidate configuration without replacing the live configuration.
4. For a database change, take the project-approved backup or restore point.
   Prefer expand/contract migrations that allow both old and new application
   versions to run. Do not automatically apply an irreversible migration
   without explicit authority and a tested recovery plan.
5. Activate with the repository-owned command in no-build mode. Use an atomic
   pointer/symlink swap for static releases when the project supports it. On a
   single small host, use a controlled short replacement if running old and new
   releases together would exhaust memory.
6. Verify in order: process/container state, local origin health, local proxy
   route, then public DNS/TLS/HTTP from the development machine. Verify every
   required hostname, not just one convenient endpoint.
7. Inspect fresh logs and restart/OOM counters. Require several consecutive
   successful health intervals over the project's observation window; absent a
   project rule, observe for at least 60 seconds.
8. Record the active artifact digest, migration revision, verification result,
   and rollback identifier before releasing the deployment lock.

Never declare success from `docker ps`, SSH reachability, or a single HTTP 200
alone. Use the layered health model in `servers.md`.

## Bounded source synchronization

Treat source synchronization as control-plane preparation, not as the runtime
artifact build. Prefer fetching an exact Git revision into a clean versioned
release directory. Never reset or overwrite an unknown dirty production
checkout.

When a project explicitly requires `rsync` or file upload:

1. Resolve and display the exact local source and remote destination.
2. Read the project's persistence/exclusion list and protect at least populated
   environment files, secrets, databases, uploads, backups, logs, runtime data,
   and already-built server-owned assets.
3. Run a dry-run and inspect additions, replacements, and deletions.
4. Use `--delete` only inside a verified, dedicated release directory whose
   complete contents are owned by that synchronization. Never aim it at a home
   directory, repository root containing state, or shared deployment root.
5. Transfer bounded files, verify checksums, then activate through the normal
   release path. Do not run an unbounded recursive copy directly over the live
   tree.

## Exceptional on-host build fallback

This section does not clear the release safety gate or authorize a fallback by
itself. Consider an on-host build only when the repository has no viable
off-host artifact path, the requested release cannot otherwise be delivered,
and the user explicitly authorizes this named exception after receiving the
risk and correct off-host path. State the exception and preserve the current
live release while building.

Before building:

- prove that the build worker, not merely the shell/CLI process, is placed in a
  constrained cgroup or container;
- give live services higher CPU and I/O priority;
- cap build memory below the amount needed by the live workload plus reserve;
- apply cgroup-v2 I/O weight or measured per-device bandwidth/IOPS limits when
  supported, and verify that they actually cover BuildKit workers;
- run only one build job and disable parallel maintenance/cleanup;
- monitor origin health, restarts, OOM events, free disk, and I/O pressure from
  a separate control path throughout the build.

Confining only `docker build` or `docker compose` client processes is
insufficient when the daemon or BuildKit worker performs the real work outside
that cgroup. If worker-level controls cannot be verified, do not build on the
fragile production host.

If any prerequisite above cannot be proven before mutation, the refusal is
final for that release attempt. Return the off-host immutable-artifact path and
the exact prerequisite needed to make it usable; do not negotiate the gate down
to client-only CPU/memory limits.

Cancel the build while leaving the current release active if origin health
fails on two consecutive checks, OOM/restart events appear, disk reserve is
crossed, or the host becomes unresponsive. Never proceed from a stressed build
directly into cutover without a fresh preflight.

## Rollback and cleanup

- If staging or verification fails before activation, remove only the bounded
  candidate and leave the current release untouched.
- If cutover fails and the schema remains compatible, restore the exact prior
  image/static pointer/configuration and repeat all health layers.
- Do not blindly roll back application code after an incompatible database
  migration. Follow the pre-reviewed database recovery plan.
- Keep the failed release evidence and a redacted log summary until the cause is
  understood.
- Schedule cleanup after the new release is stable, under the same lock and
  preflight. Remove only named stale artifacts.

Never run broad commands such as `docker system prune -a` as part of a release.
Never delete the current release, the immediate rollback release, persistent
volumes, caches needed for recovery, or server-owned state to make a deployment
fit.

## Completion evidence

Report a compact release record:

```text
Target identity: verified
Release: source revision + immutable artifact digest/checksums
Build location: development/CI (or documented exception)
Preflight and lock: passed
Migration: none / revision + recovery plan
Origin / ingress / public checks: passed per layer
Observation: duration + consecutive passes
Rollback: exact previous release retained and identified
Cleanup: deferred / bounded artifacts removed
```

A file transfer, image pull, container start, or migration completion is not by
itself a successful deployment.
