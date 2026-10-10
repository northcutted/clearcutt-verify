# ClearCutt Verify Documentation

Use this page as the documentation front door. Each role gets one first
document, one first command, and then deeper links.

| Role | First document | First command | Then read |
| --- | --- | --- | --- |
| Estate owner | [Registry scan and the base image graph](registry-graph.md) | `clearcutt-verify registry scan --registry ghcr.io --namespace YOUR_ORG --repository YOUR_IMAGE --output /tmp/images.yaml` | [Registry-native evidence](registry-native-evidence.md), [Imported fleets](imported-fleets.md) |
| Security or auditor | [Verifying an estate](verify-estate.md) | `clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out /tmp/estate` | [The estate report contract](../contract/README.md), [Security model](security-model.md) |
| Imported fleet owner | [Imported fleets](imported-fleets.md) | `clearcutt-verify import images --refs examples/imported-fleet/refs.txt --output /tmp/images.yaml --force` | [Registry scan and the base image graph](registry-graph.md) |
| Manager | [Alternatives and fit](alternatives.md) | `sed -n '1,120p' docs/alternatives.md` | [Mental model](concepts/mental-model.md) |

## One word: estate

An **estate** is what ClearCutt Verify governs: whatever is in your registry,
including images you did not build, cannot rebuild, and did not choose. An
estate is discovered, not declared.

## Guides

- [Mental model](concepts/mental-model.md): the governance loop and what each
  step proves.
- [Registry scan and the base image graph](registry-graph.md): point
  clearcutt-verify at a registry, discover which images are built on which, and
  produce an auditable inventory with drift.
- [Verifying an estate](verify-estate.md): verify every image's signatures and
  attestations against a trust policy, write the estate report
  ([contract](../contract/README.md)) a portal reads, list a base's dependents,
  and keep the report in the registry.
- [Verifying an estate in GitHub Actions](github-actions.md): the scheduled
  job, verified install, registry credentials, history, and exit codes.
- [Imported fleets](imported-fleets.md): import existing OCI refs, observe
  evidence without provenance claims, and assess governance gaps.
- [Registry-native evidence](registry-native-evidence.md): store evidence,
  estate snapshots and history in the registry, plus the two operational
  constraints that come with it (garbage collection, and which tags must stay
  mutable).
- [CLI reference](cli-reference.md): every command.
- [Security model](security-model.md): trust boundaries and non-claims.
- [Alternatives and fit](alternatives.md): when to use something else.
