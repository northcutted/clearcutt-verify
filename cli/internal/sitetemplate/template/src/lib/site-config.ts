import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';

const SiteConfigInput = z
  .object({
    site: z
      .object({
        title: z.string().optional(),
        description: z.string().optional(),
        logo: z.string().optional(),
		catalogMode: z.enum(['fleet', 'imported']).optional(),
        theme: z
          .object({
            mode: z.enum(['system', 'light', 'dark']).optional(),
            accent: z.string().optional(),
          })
          .optional(),
        navigation: z
          .object({
            showHome: z.boolean().optional(),
            showEstate: z.boolean().optional(),
            showMarketingHome: z.boolean().optional(),
            showGettingStarted: z.boolean().optional(),
            showOperatorDocs: z.boolean().optional(),
            showCliDocs: z.boolean().optional(),
            showAuditGuide: z.boolean().optional(),
          })
          .optional(),
        features: z
          .object({
            sbomTable: z.boolean().optional(),
            vulnerabilityTable: z.boolean().optional(),
            layerExplorer: z.boolean().optional(),
            provenance: z.boolean().optional(),
            ociLabels: z.boolean().optional(),
            versionHistory: z.boolean().optional(),
            kyvernoPolicies: z.boolean().optional(),
          })
          .optional(),
        terminology: z
          .object({
            distroless: z.string().optional(),
            slim: z.string().optional(),
            dev: z.string().optional(),
          })
          .optional(),
        links: z
          .object({
            sourceRepo: z.string().optional(),
            registry: z.string().optional(),
            support: z.string().optional(),
            docs: z.string().optional(),
          })
          .optional(),
        home: z
          .object({
            title: z.string().optional(),
            description: z.string().optional(),
            showNotice: z.boolean().optional(),
            noticeTitle: z.string().optional(),
            noticeBody: z.string().optional(),
            quickLinks: z
              .array(
                z.object({
                  label: z.string(),
                  href: z.string(),
                  description: z.string().optional(),
                }),
              )
              .optional(),
            personas: z
              .array(
                z.object({
                  id: z.string(),
                  label: z.string(),
                  summary: z.string(),
                  steps: z.array(
                    z.object({
                      title: z.string(),
                      description: z.string(),
                      href: z.string().optional(),
                      command: z.string().optional(),
                      ctaLabel: z.string().optional(),
                    }),
                  ),
                }),
              )
              .optional(),
          })
          .optional(),
      })
      .optional(),
  })
  .optional();

type HomeQuickLink = {
  label: string;
  href: string;
  description?: string;
};

type HomeStep = {
  title: string;
  description: string;
  href?: string;
  command?: string;
  ctaLabel?: string;
};

type HomePersona = {
  id: string;
  label: string;
  summary: string;
  steps: HomeStep[];
};

export type SiteConfig = {
  site: {
    title: string;
    description: string;
    logo: string;
	catalogMode: 'fleet' | 'imported';
    theme: {
      mode: 'system' | 'light' | 'dark';
      accent: string;
    };
    navigation: {
      showHome: boolean;
      showEstate: boolean;
      showGettingStarted: boolean;
      showOperatorDocs: boolean;
      showCliDocs: boolean;
      showAuditGuide: boolean;
    };
    features: {
      sbomTable: boolean;
      vulnerabilityTable: boolean;
      layerExplorer: boolean;
      provenance: boolean;
      ociLabels: boolean;
      versionHistory: boolean;
      kyvernoPolicies: boolean;
    };
    terminology: {
      distroless: string;
      slim: string;
      dev: string;
    };
    links: {
      sourceRepo: string;
      registry: string;
      support: string;
      docs: string;
    };
    home: {
      title: string;
      description: string;
      showNotice: boolean;
      noticeTitle: string;
      noticeBody: string;
      quickLinks: HomeQuickLink[];
      personas: HomePersona[];
    };
  };
};

export const defaultSiteConfig: SiteConfig = {
  site: {
    title: 'ClearCutt Catalog',
    description:
      'Static evidence portal for base-image signatures, SBOMs, provenance, vulnerability findings, and runtime contracts.',
    logo: '',
	catalogMode: 'fleet',
    theme: {
      mode: 'system',
      accent: '#7c3aed',
    },
    navigation: {
      showHome: true,
      showEstate: true,
      showGettingStarted: true,
      showOperatorDocs: true,
      showCliDocs: true,
      showAuditGuide: true,
    },
    features: {
      sbomTable: true,
      vulnerabilityTable: true,
      layerExplorer: true,
      provenance: true,
      ociLabels: true,
      versionHistory: true,
      kyvernoPolicies: false,
    },
    terminology: {
      distroless: 'Distroless',
      slim: 'Slim',
      dev: 'Dev',
    },
    links: {
      sourceRepo: '',
      registry: '',
      support: '',
      docs: '',
    },
    home: {
      title: 'Container Image Estate',
      description:
        'What is in this registry, what each image is built on, and what can actually be proven about it. Evidence that is missing is shown as missing.',
      showNotice: true,
      noticeTitle: 'How to read this',
      noticeBody:
        'This is a static view of observed image metadata and collected evidence. A missing signature, SBOM, provenance or scan is shown as an explicit gap — do not infer trust for it from another channel. Relationships proven by layer digests are labelled differently from ones the image author asserted.',
      quickLinks: [
        {
          label: 'Map your estate',
          href: 'estate',
          description: 'See which images are built on what, and how far each has drifted from its base.',
        },
        {
          label: 'Containerize your app',
          href: 'getting-started',
          description: 'Copy a multi-stage container example and local validation commands.',
        },
        {
          label: 'Browse reference images',
          href: 'catalog',
          description: 'The four LTS runtime lines this repo publishes as build fixtures.',
        },
        {
          label: 'Audit evidence',
          href: 'about?tab=audit',
          description: 'Verify signatures, provenance, SBOMs, and workflow identity.',
        },
        {
          label: 'Know limits',
          href: 'limitations',
          description: 'Review what the catalog proves and what your team still owns.',
        },
      ],
      personas: [
        {
          id: 'platform',
          label: 'Platform engineers',
          summary: 'Publish, govern, and maintain the approved image fleet.',
          steps: [
            {
              title: 'Check catalog coverage',
              description: 'Confirm latest images, pending matrix slots, services, and evidence counts.',
              href: 'catalog',
              ctaLabel: 'Open matrix',
            },
            {
              title: 'Bootstrap the control plane',
              description: 'Render a catalog-only repo first, then graduate to the fleet profile when ClearCutt should build images.',
              ctaLabel: 'Open bootstrap guide',
            },
            {
              title: 'Publish refreshed catalog data',
              description: 'Generate catalog data and build the static site artifact for your own registry.',
              command: 'clearcutt-verify catalog site build --catalog ./dist/catalog --output ./dist/site --install',
            },
          ],
        },
        {
          id: 'application',
          label: 'Application engineers',
          summary: 'Pick a runtime image, build an app container, and validate it before release.',
          steps: [
            {
              title: 'Choose a runtime and tier',
              description: 'Use the catalog matrix to find the right language version and production tier.',
              href: 'catalog',
              ctaLabel: 'Choose an image',
            },
            {
              title: 'Copy the build pattern',
              description: 'Start with a dev-to-runtime multi-stage example that does not require Nix locally.',
              href: 'getting-started',
              ctaLabel: 'Copy app pattern',
            },
            {
              title: 'Plan rebase and certification',
              description: 'Use app lifecycle examples for app build, diff-base, certify, and rebase workflows.',
              href: 'app-lifecycle',
              ctaLabel: 'Open lifecycle',
            },
          ],
        },
        {
          id: 'audit',
          label: 'Security and audit engineers',
          summary: 'Review evidence channels, vulnerability state, and threat-model boundaries.',
          steps: [
            {
              title: 'Verify supply-chain evidence',
              description: 'Run the audit guide checks for keyless signatures, SLSA provenance, and SBOMs.',
              href: 'about?tab=audit',
              ctaLabel: 'Verify evidence',
            },
            {
              title: 'Inspect vulnerabilities',
              description: 'Use image detail pages to review active findings, fix state, OpenVEX notes, and exceptions.',
              href: 'catalog',
              ctaLabel: 'Inspect findings',
            },
            {
              title: 'Read the boundaries',
              description: 'Confirm what shell-free, provenance, and remediation claims do and do not prove.',
              href: 'limitations',
              ctaLabel: 'Read limits',
            },
          ],
        },
      ],
    },
  },
};

let cachedConfig: SiteConfig | null = null;

export function loadSiteConfig(): SiteConfig {
  if (cachedConfig) return cachedConfig;
  const file = path.resolve(process.cwd(), 'clearcutt.site.yaml');
  if (!fs.existsSync(file)) {
    cachedConfig = defaultSiteConfig;
    return cachedConfig;
  }
  const raw = parse(fs.readFileSync(file, 'utf8'));
  const parsed = SiteConfigInput.parse(raw) ?? {};
  cachedConfig = mergeSiteConfig(parsed);
  return cachedConfig;
}

export function accentStyle(config: SiteConfig): string | undefined {
  const rgb = hexToRGBTriple(config.site.theme.accent);
  if (!rgb) return undefined;
  return `--accent: ${rgb};`;
}

export function tierLabel(config: SiteConfig, id: string): string {
  const key = id as keyof SiteConfig['site']['terminology'];
  return config.site.terminology[key] ?? titleCase(id);
}

function mergeSiteConfig(input: z.infer<typeof SiteConfigInput>): SiteConfig {
  const site = input?.site ?? {};
  const navigation = {
    ...defaultSiteConfig.site.navigation,
    ...site.navigation,
  };
  if (site.navigation?.showHome === undefined && site.navigation?.showMarketingHome !== undefined) {
    navigation.showHome = site.navigation.showMarketingHome;
  }
  return {
    site: {
      ...defaultSiteConfig.site,
      ...site,
      theme: {
        ...defaultSiteConfig.site.theme,
        ...site.theme,
      },
      navigation,
      features: {
        ...defaultSiteConfig.site.features,
        ...site.features,
      },
      terminology: {
        ...defaultSiteConfig.site.terminology,
        ...site.terminology,
      },
      links: {
        ...defaultSiteConfig.site.links,
        ...site.links,
      },
      home: {
        ...defaultSiteConfig.site.home,
        ...site.home,
        quickLinks: site.home?.quickLinks ?? defaultSiteConfig.site.home.quickLinks,
        personas: site.home?.personas ?? defaultSiteConfig.site.home.personas,
      },
    },
  };
}

function hexToRGBTriple(value: string): string | null {
  const match = /^#?([0-9a-f]{6})$/i.exec(value.trim());
  if (!match) return null;
  const hex = match[1];
  return [
    Number.parseInt(hex.slice(0, 2), 16),
    Number.parseInt(hex.slice(2, 4), 16),
    Number.parseInt(hex.slice(4, 6), 16),
  ].join(' ');
}

function titleCase(value: string): string {
  return value
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
