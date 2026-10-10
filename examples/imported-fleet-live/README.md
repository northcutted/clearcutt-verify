# Imported Fleet Live Demo

## Purpose

This example is the optional live-registry version of the imported-fleet demo.
It shows ClearCutt importing image references it did not build, observing
registry metadata, mapping base relationships, assessing governance gaps, and
writing a report without treating imported images as trusted by default.

## How to create refs.txt

Copy the public example file, then replace the commented placeholders with
digest-pinned images from registries you are allowed to inspect:

```bash
cp examples/imported-fleet-live/refs.public.example examples/imported-fleet-live/refs.txt
$EDITOR examples/imported-fleet-live/refs.txt
```

Use only manually verified digest-pinned references for repeatable output. Tag
references are accepted by the CLI for manual exploration, but tags can move
between runs and should not be used for the checked-in public example.

## How to run the live demo

```bash
./scripts/demo-imported-fleet-live.sh
```

To use a different refs file or output directory:

```bash
REFS=/path/to/refs.txt OUT=/tmp/my-imported-fleet ./scripts/demo-imported-fleet-live.sh
```

## What this proves

- ClearCutt can govern images it did not build.
- ClearCutt can observe available registry metadata for imported images.
- ClearCutt can preserve missing evidence as governance gaps.
- ClearCutt can produce assessment and report artifacts for an imported fleet.
- ClearCutt can prove base relationships by layer digest where they exist.

## What this does not prove

- ClearCutt cannot infer build provenance.
- ClearCutt cannot prove source repository or build workflow for arbitrary
  imported images.
- ClearCutt does not make imported images trusted by default.

## Why missing provenance is expected

Imported images were built outside ClearCutt. Unless those images publish
verifiable provenance that ClearCutt can observe or verify, the correct report
state is missing provenance.

## Why observed evidence is not build provenance

Registry metadata, labels, annotations, SBOM references, and vulnerability scan
artifacts can be useful governance evidence, but they do not prove the source
repository, workflow identity, or build inputs for the image. ClearCutt records
observed evidence separately from verified provenance.

## Why output may vary over time

This demo contacts live registries. Public registries can rate-limit requests,
delete images, change permissions, omit referrer APIs, or change which evidence
channels are discoverable. Use digest-pinned refs when you need repeatable
output.
