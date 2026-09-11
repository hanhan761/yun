# 本机目标登记表

`yunctl.py` resolves the registry from `YUN_TARGETS_FILE` when set; otherwise it
uses `~/.config/yun/targets.json`. It is reproducible cache: `import-pem` can
rebuild an entry and its dedicated host-key file from one self-describing PEM.
It contains operational metadata, not credentials, but must not be committed.

Create or inspect it with:

```text
python scripts/yunctl.py init
python scripts/yunctl.py registry-path
python scripts/yunctl.py targets
```

Use `register` during initial trusted onboarding or `import-pem` when receiving
an already bundled PEM. Replacing an existing target requires its name twice:

```text
python scripts/yunctl.py register TARGET ... --confirm-replace TARGET
python scripts/yunctl.py import-pem /path/yun_TARGET.pem --confirm-replace TARGET
```

Each entry records:

- a local target name and description;
- direct hostname, port, and SSH user;
- optional `platform`: `linux` or `windows`; absence preserves legacy Linux behavior;
- one absolute `.pem` identity path for that target;
- one absolute dedicated known-hosts path;
- the independently verified `SHA256:` server host-key fingerprint;
- `server` and/or `compute` roles;
- whether writes need protected-target confirmation;
- the fixed detached-job backend/root when compute is enabled.

Register Windows with `--platform windows --role server`. Numeric local usernames
and ASCII `domain\user` names are supported. Windows rejects the `compute` role.
The YUN-BUNDLE-V1 connection object accepts an optional `platform` field; all old
required fields and fingerprint checks remain mandatory. Bundling and importing
preserve the field. Legacy PEMs and registry entries without it keep their exact
shape and Linux semantics. Old yun versions reject Windows PEMs as unsupported
metadata rather than interpreting them as Linux; carry the upgraded skill too.

The registry never stores private-key bytes, key passphrases, passwords, cloud
tokens, populated environment variables, or application secrets. `targets
--json` may expose operational metadata, so return it only when the user asks.

Every operation disables SSH config with `-F none`, disables ambient agents,
and passes the registered PEM and known-hosts file explicitly. Moving either
file requires an explicitly confirmed target replacement. The registry rejects
one PEM path shared by two targets.

Imported host-key cache lives beneath the registry directory at
`known_hosts/TARGET.known_hosts`. Deleting this cache is recoverable by importing
the PEM again; changing an existing entry or cache requires exact replacement
confirmation. Never store the PEM itself beside or inside the Skill.

Use `YUN_TARGETS_FILE` for an isolated test registry or controlled automation;
do not point it at a repository path that will be committed.
