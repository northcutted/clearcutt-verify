// Shared runtime taxonomy helpers for the catalog UI.
//
// `displayLanguage` and `isPrimaryRuntimePackage` were previously copy-pasted
// into VulnerabilityTable.tsx and SbomTable.tsx (and mirrored in
// `clearcutt-verify scan`, which is the authoritative *producer* of the
// `inclusion`/`remediation` metadata the client only recomputes as a fallback).
// Centralizing the two pure predicates here keeps the CVE table and SBOM table
// from drifting apart. The scanner intentionally keeps its own copy in Go; if
// you change the rules here, update cli/internal/commands/scan.go to match.

export function displayLanguage(language: string): string {
  switch (language) {
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
    case 'rust':
      return 'Rust';
    case 'cc':
      return 'C/C++';
    default:
      return language;
  }
}

// True when the package IS the language runtime ClearCutt overlays into the
// image (as opposed to a transitive dependency or base-OS package).
export function isPrimaryRuntimePackage(language: string, packageName: string): boolean {
  const pkg = packageName.toLowerCase();
  switch (language) {
    case 'python':
      return pkg === 'python' || /^python[0-9.]*$/.test(pkg);
    case 'java':
      return pkg.includes('jdk') || pkg.includes('jre') || pkg.includes('openjdk') || pkg.includes('zulu');
    case 'node':
      return pkg === 'node' || pkg === 'nodejs' || pkg.startsWith('nodejs');
    case 'go':
      return pkg === 'go' || pkg.startsWith('go-') || /^go_[0-9_]+$/.test(pkg);
    case 'dotnet':
      return pkg.includes('dotnet') || pkg.includes('aspnetcore');
    case 'rust':
      return pkg === 'rustc' || pkg === 'cargo';
    case 'cc':
      return pkg === 'gcc' || pkg === 'clang';
    default:
      return false;
  }
}
