import { useState, useEffect, useRef } from 'react';

type CommandOption = {
  name: string;
  command: string;
  output: string[];
};

type Props = {
  registryBase?: string;
  java21ImageName?: string;
};

function commandOptions(registryBase: string, java21ImageName: string): CommandOption[] {
  const java21 = `${registryBase}/${java21ImageName}`;

  return [
    {
      name: 'clearcutt-verify inspect',
      command: 'clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless',
      output: [
        'Image Metadata Report for java21-distroless',
        '-----------------------------------------------------------------',
        'ID                     : java21-distroless',
        `Registry               : ${registryBase}`,
        `FullName               : ${java21}`,
        'Runtime Line           : java21',
        'Tier                   : distroless (hardened, shell-free)',
        'Latest Release Version : vX.Y.Z',
        'Digest                 : sha256:8894dfc15a7721ff07d1ea21b2d7f5ca9158ba6ea6afe058ab6d1bd854f0466e',
        'Architectures          : amd64, arm64',
        'Size (Total)           : 48.7 MB',
        'Non-Root Execution     : Yes (UID 10001)',
        'CA Bundle Present      : Yes (/etc/ssl/certs/ca-certificates.crt)',
        'Timezone Database      : Yes (/usr/share/zoneinfo)',
        '-----------------------------------------------------------------',
        'Vulnerability Summary:',
        '  Critical : 0',
        '  High     : 2',
        '  Medium   : 12',
        '  Low      : 8',
        '  Active Exception Mappings : 1 (CVE-2026-9999 resolved)',
        '-----------------------------------------------------------------',
        'Status: ACTIVE (LTS Preview)'
      ]
    },
    {
      name: 'clearcutt-verify verify',
      command: 'clearcutt-verify --catalog cli/internal/testdata/catalog verify image java21-distroless --max-critical 0 --max-high 3 --allow-preview',
      output: [
        'Policy Gating Report for java21-distroless:vX.Y.Z',
        '-----------------------------------------------------------------',
        '[✔ PASS] digest.present                  : manifest digest present: sha256:8894dfc1...',
        '[✔ PASS] architectures.present           : architectures present: amd64, arm64',
        '[✔ PASS] signature.present               : catalog release record reports Sigstore signature evidence',
        '[✔ PASS] sbom.present                    : catalog release record reports SPDX SBOM evidence for all platforms',
        '[✔ PASS] provenance.present              : catalog release record reports SLSA provenance evidence',
        '[✔ PASS] tests.passed                    : conformance and smoke tests passed on all platforms',
        '[✔ PASS] vulnerabilities.scanned         : vulnerability scan results present for all platforms',
        '[✔ PASS] lifecycle.status                : lifecycle status verified: preview',
        '[✔ PASS] vulnerabilities.threshold.crit  : critical vulnerabilities within limits (0 found, max 0)',
        '[✔ PASS] vulnerabilities.threshold.high  : high vulnerabilities within limits (2 found, max 3)',
        '-----------------------------------------------------------------',
        'Verification Result: PASS'
      ]
    },
    {
      name: 'clearcutt-verify app rebase',
      command: 'clearcutt-verify app rebase --image ghcr.io/acme/my-app:1.0.0 --candidate-base java21-distroless --sign --attest',
      output: [
        '[rebase] pulling image metadata for ghcr.io/acme/my-app:1.0.0...',
        `[rebase] resolved base image reference: ${java21}@sha256:a78b...`,
        '[rebase] verifying dynamic ABI compatibility...',
        '  - Current Base: java21-distroless (v0.16.0)',
        '  - Candidate Base: java21-distroless (vX.Y.Z - Patched)',
        '  - Result: ✔ COMPATIBLE (java21 preserved, major/minor matches)',
        '[rebase] extracting application layers...',
        '  - Found 1 application-specific layer (sha256:e32d6619...)',
        '[rebase] performing layer rebase swap...',
        '  - Dropped old base layers (v0.16.0)',
        '  - Grafted candidate base layers (vX.Y.Z)',
        '  - Preserved application layers byte-for-byte (sha256:e32d6619...)',
        '[rebase] generating signed rebase attestation...',
        '  - Subject: ghcr.io/acme/my-app:1.0.0-rebased',
        '  - Developer Signature: ✔ VERIFIED',
        '  - Attestation Decision: ALLOWED',
        '[rebase] pushing rebased image to registry...',
        '  - Pushed: ghcr.io/acme/my-app:1.0.0-rebased',
        '  - Pushed attestation referrer index',
        '[rebase] Success! Rebase complete in 1.4s.'
      ]
    }
  ];
}

export default function TerminalSimulator({
  registryBase = 'ghcr.io/northcutted/clearcutt',
  java21ImageName = 'clearcutt-java21',
}: Props) {
  const commands = commandOptions(registryBase, java21ImageName);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [displayedCommand, setDisplayedCommand] = useState('');
  const [displayedOutput, setDisplayedOutput] = useState<string[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const typingTimer = useRef<NodeJS.Timeout | null>(null);
  const outputTimer = useRef<NodeJS.Timeout | null>(null);

  const startSimulation = (idx: number) => {
    // Clear any active timers
    if (typingTimer.current) clearTimeout(typingTimer.current);
    if (outputTimer.current) clearTimeout(outputTimer.current);

    setSelectedIdx(idx);
    setDisplayedCommand('');
    setDisplayedOutput([]);
    setIsTyping(true);
    setIsRunning(false);

    const fullCommand = commands[idx].command;
    let charIdx = 0;

    const typeCharacter = () => {
      if (charIdx < fullCommand.length) {
        setDisplayedCommand(prev => prev + fullCommand[charIdx]);
        charIdx++;
        typingTimer.current = setTimeout(typeCharacter, 20);
      } else {
        setIsTyping(false);
        setIsRunning(true);
        // Start rendering output lines one by one after a short delay
        let lineIdx = 0;
        const targetOutput = commands[idx].output;
        
        const renderLine = () => {
          if (lineIdx < targetOutput.length) {
            const nextLine = targetOutput[lineIdx];
            setDisplayedOutput(prev => [...prev, nextLine]);
            lineIdx++;
            outputTimer.current = setTimeout(renderLine, idx === 2 ? 80 : 30); // Rebase output runs a bit slower to feel like a real action
          } else {
            setIsRunning(false);
          }
        };

        outputTimer.current = setTimeout(renderLine, 300);
      }
    };

    typingTimer.current = setTimeout(typeCharacter, 100);
  };

  useEffect(() => {
    startSimulation(0);
    return () => {
      if (typingTimer.current) clearTimeout(typingTimer.current);
      if (outputTimer.current) clearTimeout(outputTimer.current);
    };
  }, []);

  return (
    <div className="surface-soft border border-ink-800/60 rounded-2xl overflow-hidden shadow-2xl flex flex-col font-sans">
      {/* Selector Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-ink-800/60 bg-ink-900/60 px-4 py-3">
        <div className="flex gap-2">
          {commands.map((cmd, idx) => (
            <button
              key={cmd.name}
              type="button"
              onClick={() => startSimulation(idx)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
                selectedIdx === idx
                  ? 'bg-accent/15 text-accent-soft border border-accent/25'
                  : 'text-ink-300 hover:text-ink-100 border border-transparent'
              }`}
            >
              {cmd.name}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2.5 select-none shrink-0">
          <span className="rounded bg-ink-800/80 border border-ink-700 px-1.5 py-0.5 text-[8px] font-mono font-bold uppercase tracking-wider text-ink-400" title="Scripted sample output, not a live command run">
            Illustrative
          </span>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-500/80" />
            <span className="h-2 w-2 rounded-full bg-yellow-500/80" />
            <span className="h-2 w-2 rounded-full bg-green-500/80" />
          </div>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="bg-ink-950 p-5 font-mono text-xs text-ink-100 min-h-[320px] flex flex-col gap-3 max-h-[440px] overflow-y-auto leading-relaxed select-text">
        {/* Terminal Input Line */}
        <div className="flex items-center gap-2 text-ink-300 select-none">
          <span className="text-accent-soft font-bold">~</span>
          <span className="text-ink-400 font-semibold">$</span>
          <span className="text-ink-100 font-mono flex-1">
            {displayedCommand}
            {isTyping && <span className="animate-pulse bg-accent-soft w-1.5 h-3.5 inline-block align-middle ml-0.5" />}
          </span>
        </div>

        {/* Output lines */}
        <div className="space-y-1.5 font-mono text-[11px] text-ink-200">
          {displayedOutput.map((line, idx) => {
            const safeLine = line ?? '';
            const isPass = safeLine.includes('[✔ PASS]') || safeLine.includes('Success!') || safeLine.includes('✔ COMPATIBLE') || safeLine.includes('✔ VERIFIED') || safeLine.includes('Result: PASS');
            const isWarning = safeLine.includes('[rebase]') || safeLine.includes('High     :');
            const textColor = isPass ? 'text-emerald-400' : isWarning ? 'text-accent-soft' : 'text-ink-200';
            
            return (
              <div key={idx} className={`${textColor} whitespace-pre-wrap`}>
                {safeLine}
              </div>
            );
          })}
          {isRunning && !isTyping && (
            <div className="text-ink-400 animate-pulse text-[10px]">Processing request...</div>
          )}
        </div>
      </div>
    </div>
  );
}
