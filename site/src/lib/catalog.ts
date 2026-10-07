import fs from 'node:fs';
import path from 'node:path';
import {
  CatalogIndex,
  ImageRecord,
  type CatalogIndex as CatalogIndexT,
  type ImageRecord as ImageRecordT,
} from './catalog-schema';

// Astro runs build steps with cwd set to the project root. The source repo keeps
// generated data under src/data/catalog, while scaffolded sites copy portable
// catalog artifacts under public/catalog so they are also deployed as static
// assets.
const DATA_ROOTS = [
  path.resolve(process.cwd(), 'public/catalog'),
  path.resolve(process.cwd(), 'src/data/catalog'),
];

let cachedIndex: CatalogIndexT | null = null;

export function loadIndex(): CatalogIndexT {
  if (cachedIndex) return cachedIndex;
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, 'index.json');
  if (!fs.existsSync(file)) {
    throw new Error(
      `Catalog index not found at ${file}. Run clearcutt-verify catalog generate first.`,
    );
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  cachedIndex = CatalogIndex.parse(raw);
  return cachedIndex;
}

export function loadImage(id: string): ImageRecordT {
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, 'images', `${id}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Image record not found: ${id}`);
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  return ImageRecord.parse(raw);
}

export function loadCatalogArtifact(relativePath: string): string {
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, relativePath);
  if (!fs.existsSync(file)) {
    throw new Error(`Catalog artifact not found: ${relativePath}`);
  }
  return fs.readFileSync(file, 'utf8');
}

export function listImageIds(): string[] {
  return loadIndex().images.map((image) => image.id);
}

function resolveDataRoot(): string {
  for (const root of DATA_ROOTS) {
    if (fs.existsSync(path.join(root, 'index.json'))) {
      return root;
    }
  }
  return DATA_ROOTS[0];
}

export function tierDescription(id: 'dev' | 'slim' | 'distroless'): string {
  switch (id) {
    case 'dev':
      return 'Builder tier — full toolchain, shells, debug utilities, credential helper.';
    case 'slim':
      return 'Runtime tier — language runtime plus minimal troubleshooting binaries.';
    case 'distroless':
      return 'Hardened tier — no shells, no coreutils, runtime only.';
  }
}

export function languageDisplayName(id: string): string {
  switch (id) {
    case 'core':
      return 'Core';
    case 'java':
      return 'Java';
    case 'node':
      return 'Node.js';
    case 'python':
      return 'Python';
    case 'go':
      return 'Go';
    case 'dotnet':
      return '.NET';
    default:
      return id;
  }
}
