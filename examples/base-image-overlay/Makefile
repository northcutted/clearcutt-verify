SYSTEM ?= x86_64-linux
IMAGE_REF ?= ghcr.io/acme/java21-ubi:latest
RUNTIME_REF ?= ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless@sha256:REPLACE_WITH_RUNTIME_DIGEST
GRAFTED_REF ?= $(IMAGE_REF)@sha256:REPLACE_WITH_GRAFTED_DIGEST
RUNTIME_ARCHIVE ?= clearcutt-runtime.tar
GRAFTED_ARCHIVE ?= result

.PHONY: build predicate

build:
	nix build .#packages.$(SYSTEM).overlayImage

predicate:
	clearcutt-verify overlay verify \
	  --runtime-archive $(RUNTIME_ARCHIVE) \
	  --grafted-archive $(GRAFTED_ARCHIVE) \
	  --runtime-ref $(RUNTIME_REF) \
	  --grafted-ref $(GRAFTED_REF) \
	  --target java21-distroless \
	  --output-predicate > closure-equivalence.intoto.json
