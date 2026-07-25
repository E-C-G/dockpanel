import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "../api";

// The guidance layer's renderer.
//
// One component, keyed on CONSEQUENCE rather than on how confident the check is
// (brief §3A.1). The backend decides the tier — `services/prerequisites.rs` —
// and this only chooses how loudly to say it:
//
//   satisfied            → a quiet confirmation line
//   unknown / info       → passive helper text
//   unsatisfied warning  → an amber callout, control stays usable
//   unsatisfied blocking → a red callout, caller gates its control
//
// The rule is "block only when it would actually fail; warn when it probably
// will; explain passively otherwise." Nothing here decides that — it renders it.

export type PrereqState = "satisfied" | "unsatisfied" | "unknown";
export type PrereqSeverity = "blocking" | "warning" | "info";

export interface DnsRecordHint {
  name: string;
  fqdn: string;
  record_type: string;
  value: string;
  ttl: string;
}

export interface PrereqResult {
  key: string;
  state: PrereqState;
  severity: PrereqSeverity;
  title: string;
  detail: string;
  expected?: string | null;
  observed: string[];
  remediation?: DnsRecordHint | null;
}

/** A prerequisite gates a control only when it is BOTH unsatisfied and blocking. */
export function prereqBlocks(p: PrereqResult | null): boolean {
  return !!p && p.state === "unsatisfied" && p.severity === "blocking";
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // Clipboard is unavailable over plain HTTP, which is exactly how the
          // documented install is first reached. Say so instead of doing nothing.
          setCopied(false);
          window.prompt(`Copy ${label}:`, value);
        }
      }}
      className="px-2 py-0.5 bg-dark-700 text-dark-100 rounded text-[10px] font-medium hover:bg-dark-600 transition-colors shrink-0"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/**
 * The exact record to create, values filled in, every field copyable.
 *
 * Per brief §3A.3 this is deliberately the record itself rather than a
 * description of one — the user should be able to retype it into their DNS
 * provider without deciding anything.
 */
export function DnsRecordCard({ record }: { record: DnsRecordHint }) {
  const rows: Array<{ label: string; value: string; mono?: boolean }> = [
    { label: "Type", value: record.record_type, mono: true },
    { label: "Name", value: record.name, mono: true },
    { label: "Value", value: record.value, mono: true },
    { label: "TTL", value: record.ttl },
  ];

  return (
    <div className="mt-3 border border-dark-600 bg-dark-900/60 rounded overflow-hidden">
      <div className="px-3 py-2 border-b border-dark-600 text-[10px] uppercase font-mono tracking-widest text-dark-300">
        Create this record
      </div>
      <div className="divide-y divide-dark-700">
        {rows.map((r) => (
          <div key={r.label} className="px-3 py-2 flex items-center gap-3">
            <span className="text-[10px] uppercase text-dark-300 w-12 shrink-0">{r.label}</span>
            <span className={`text-xs text-dark-50 flex-1 break-all ${r.mono ? "font-mono" : ""}`}>
              {r.value}
            </span>
            <CopyButton value={r.value} label={r.label.toLowerCase()} />
          </div>
        ))}
      </div>
      <p className="px-3 py-2 text-[10px] text-dark-300 border-t border-dark-600">
        Some DNS providers want the full name instead of the host part — in that case use{" "}
        <span className="font-mono text-dark-100">{record.fqdn}</span>.
      </p>
    </div>
  );
}

interface CalloutProps {
  prereq: PrereqResult | null;
  /** Re-run the check. Renders a "Check again" button when provided. */
  onRecheck?: () => void;
  checking?: boolean;
  /** Show a quiet confirmation when the prerequisite is met. Off by default. */
  showSatisfied?: boolean;
  className?: string;
}

export function PrereqCallout({
  prereq,
  onRecheck,
  checking,
  showSatisfied = false,
  className = "",
}: CalloutProps) {
  if (!prereq) return null;

  // ── Satisfied: quiet confirmation, or nothing at all.
  if (prereq.state === "satisfied") {
    if (!showSatisfied) return null;
    return (
      <p className={`text-xs text-rust-400 ${className}`}>{prereq.title}</p>
    );
  }

  // ── Passive tier: context, no failure implied.
  if (prereq.state === "unknown" || prereq.severity === "info") {
    return (
      <p className={`text-xs text-dark-300 ${className}`}>{prereq.detail}</p>
    );
  }

  const blocking = prereq.severity === "blocking";
  const tone = blocking
    ? "border-danger-500/30 bg-danger-500/10"
    : "border-warn-500/30 bg-warn-400/10";
  const titleTone = blocking ? "text-danger-400" : "text-warn-400";

  return (
    <div role="alert" className={`border rounded p-4 ${tone} ${className}`}>
      <div className={`text-sm font-medium mb-1 ${titleTone}`}>{prereq.title}</div>

      {/* whitespace-pre-line so the backend's paragraph breaks survive */}
      <p className="text-xs text-dark-100 whitespace-pre-line">{prereq.detail}</p>

      {(prereq.expected || prereq.observed.length > 0) && (
        <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
          {prereq.expected && (
            <>
              <dt className="text-dark-300">Expected</dt>
              <dd className="font-mono text-dark-50 break-all">{prereq.expected}</dd>
            </>
          )}
          <dt className="text-dark-300">Detected</dt>
          <dd className="font-mono text-dark-50 break-all">
            {prereq.observed.length > 0 ? prereq.observed.join(", ") : "nothing"}
          </dd>
        </dl>
      )}

      {prereq.remediation && <DnsRecordCard record={prereq.remediation} />}

      {onRecheck && (
        <button
          type="button"
          onClick={onRecheck}
          disabled={checking}
          className="mt-3 px-3 py-1 bg-dark-700 text-dark-100 rounded text-xs font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
        >
          {checking ? "Checking..." : "Check again"}
        </button>
      )}
    </div>
  );
}

/**
 * Run the DNS prerequisite for a domain.
 *
 * Debounced, because the create-site form calls this as the user types, and
 * cancel-aware, because a slow lookup for a half-typed domain must never
 * overwrite the verdict for the finished one.
 *
 * `autoPoll` re-checks on an interval while the prerequisite is unmet — the
 * brief's propagation case (§3A.3: "do not present a not-yet-visible record as
 * an error; say we will keep checking"). It is what lets a blocking gate open by
 * itself the moment DNS goes live, instead of making the user guess when to
 * retry.
 */
export function useDnsPrereq(domain: string, opts?: { debounceMs?: number; autoPoll?: boolean }) {
  const { debounceMs = 600, autoPoll = false } = opts ?? {};
  const [prereq, setPrereq] = useState<PrereqResult | null>(null);
  const [checking, setChecking] = useState(false);
  const requestSeq = useRef(0);

  const run = useCallback(async (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      setPrereq(null);
      return;
    }
    const seq = ++requestSeq.current;
    setChecking(true);
    try {
      const r = await api.get<PrereqResult>(`/preflight/dns?domain=${encodeURIComponent(trimmed)}`);
      // Ignore a response that a newer request has already superseded.
      if (seq === requestSeq.current) setPrereq(r);
    } catch {
      // A failed preflight must never present as a failed prerequisite — the
      // user's DNS may be perfect and our check merely unavailable.
      if (seq === requestSeq.current) setPrereq(null);
    } finally {
      if (seq === requestSeq.current) setChecking(false);
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => run(domain), debounceMs);
    return () => clearTimeout(t);
  }, [domain, debounceMs, run]);

  useEffect(() => {
    if (!autoPoll || !prereq || prereq.state === "satisfied") return;
    const t = setInterval(() => run(domain), 20000);
    return () => clearInterval(t);
  }, [autoPoll, prereq, domain, run]);

  return { prereq, checking, recheck: () => run(domain) };
}
