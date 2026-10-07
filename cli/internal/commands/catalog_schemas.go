package commands

import (
	"os"
	"path/filepath"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func writeCatalogSchemaFiles(catalogPath string) error {
	artifacts, err := catalog.SchemaArtifacts()
	if err != nil {
		return err
	}
	schemaDir := filepath.Join(catalogPath, "schemas")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if err := os.WriteFile(filepath.Join(schemaDir, artifact.Name), artifact.Data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
