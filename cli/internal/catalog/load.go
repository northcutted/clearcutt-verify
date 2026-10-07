package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Strict, when true, causes catalog JSON to be rejected if it contains fields
// not present in the Go data model. It is wired to the global --strict flag and
// helps catch drift between the generator and the CLI's schema.
var Strict bool

func decodeJSON(data []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if Strict {
		dec.DisallowUnknownFields()
	}
	return dec.Decode(v)
}

// catalogNotFoundError returns an actionable error when the catalog directory or
// its index.json is missing, pointing the user at how to obtain a catalog rather
// than surfacing a bare "no such file" from the OS. The catalog is a generated
// artifact (see `clearcutt-verify catalog generate`) and is not committed to the repo.
func catalogNotFoundError(catalogPath, missingPath string, cause error) error {
	return fmt.Errorf(`no ClearCutt catalog found at %q (looked for %s).

The CLI reads a generated catalog of image records. To obtain one:
  - generate portable catalog data from a clone of this repo:
        clearcutt-verify catalog generate --output site/src/data/catalog
  - or run the full release-evidence pipeline:
        clearcutt-verify catalog build
  - or point --catalog at an existing catalog directory, e.g. the bundled fixture:
        clearcutt-verify list --catalog cli/internal/testdata/catalog

underlying error: %w`, catalogPath, missingPath, cause)
}

// LoadCatalogIndex reads index.json from the specified catalog directory.
func LoadCatalogIndex(catalogPath string) (*CatalogIndex, error) {
	indexPath := filepath.Join(catalogPath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, catalogNotFoundError(catalogPath, indexPath, err)
		}
		return nil, fmt.Errorf("failed to read catalog index at %s: %w", indexPath, err)
	}

	var index CatalogIndex
	if err := decodeJSON(data, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal catalog index: %w", err)
	}
	NormalizeCatalogIndex(&index)

	return &index, nil
}

// LoadImageRecord reads an image record file images/<imageID>.json from the catalog directory.
func LoadImageRecord(catalogPath, imageID string) (*ImageRecord, error) {
	recordPath := filepath.Join(catalogPath, "images", fmt.Sprintf("%s.json", imageID))
	data, err := os.ReadFile(recordPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Distinguish "the whole catalog is missing" (actionable acquisition
			// hint) from "the catalog exists but this image id is unknown".
			if _, statErr := os.Stat(filepath.Join(catalogPath, "index.json")); errors.Is(statErr, os.ErrNotExist) {
				return nil, catalogNotFoundError(catalogPath, recordPath, err)
			}
			return nil, fmt.Errorf("image %q not found in catalog %q (run `clearcutt-verify list` to see available image ids)", imageID, catalogPath)
		}
		return nil, fmt.Errorf("failed to read image record for %q at %s: %w", imageID, recordPath, err)
	}

	var record ImageRecord
	if err := decodeJSON(data, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal image record: %w", err)
	}
	NormalizeImageRecord(&record)

	return &record, nil
}

func NormalizeCatalogIndex(index *CatalogIndex) {
	if index == nil {
		return
	}
	for i := range index.Images {
		NormalizeEvidenceSummary(index.Images[i].Evidence)
		if index.Images[i].Evidence != nil {
			index.Images[i].Signed = index.Images[i].Evidence.Signature
			index.Images[i].Provenance = index.Images[i].Evidence.Provenance
			index.Images[i].Passed = index.Images[i].Evidence.Tests
		}
	}
}

func NormalizeImageRecord(record *ImageRecord) {
	if record == nil {
		return
	}
	for i := range record.Releases {
		NormalizeEvidenceSummary(record.Releases[i].Evidence)
	}
}
