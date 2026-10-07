// Package catalogbuild contains the catalog producer transforms: the SBOM,
// provenance, enrichment, and image-record assembly that turn GitHub release
// assets into the catalog JSON the site and governance commands consume.
//
// The producer types here emit explicit null fields in a fixed key order so the
// generated catalog keeps its exact shape; they are intentionally distinct from
// the omitempty-tolerant consumer types in internal/catalog. Command wiring
// (clearcutt-verify catalog gather / enrich / build) lives in internal/commands.
//
// Files:
//   - model.go       producer types, language/tier taxonomy, small helpers
//   - lifecycle.go   lifecycle + runtime-contract derivation
//   - sbom.go        SPDX SBOM parsing and compaction
//   - provenance.go  in-toto / SLSA provenance summarization
//   - record.go      image-record assembly from release assets + enrichment
//   - assets.go      release-asset lookup and SBOM cache helpers
//   - index.go       catalog index assembly and rebuild-from-disk
package catalogbuild
