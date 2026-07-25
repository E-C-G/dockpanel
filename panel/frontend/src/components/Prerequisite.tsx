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
  /** Why this record exists. Present when a set is shown (mail's five records). */
  purpose?: string | null;
  /** Whether this particular record was found published. Absent = not checked. */
  present?: boolean | null;
}

/**
 * The concrete fix for an unmet prerequisite, tagged by `kind`.
 *
 * A closed set of SHAPES, not prose: every arm is something this renderer can
 * turn into an action — copy this, fill this in, go here — rather than a sentence
 * the user has to translate into one.
 */
export type Remediation =
  | { kind: "dns_record"; record: DnsRecordHint }
  | { kind: "dns_records"; records: DnsRecordHint[] }
  | { kind: "value"; label: string; value: string; applies_to: string; secret?: boolean }
  | { kind: "link"; label: string; href: string };

export interface PrereqResult {
  key: string;
  state: PrereqState;
  severity: PrereqSeverity;
  title: string;
  detail: string;
  expected?: string | null;
  observed: string[];
  remediation?: Remediation | null;
}

/** A prerequisite gates a control only when it is BOTH unsatisfied and blocking. */
export function prereqBlocks(p: PrereqResult | null): boolean {
  return !!p && p.state === "unsatisfied" && p.severity === "blocking";
}

/** The first result in a set that gates its control, if any. */
export function firstBlocker(results: PrereqResult[] | null): PrereqResult | null {
  return results?.find(prereqBlocks) ?? null;
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

  // When a record's published state was checked, say so on the card itself —
  // in a set of five, "which one is missing" is the entire question.
  const checked = record.present === true || record.present === false;

  return (
    <div className="mt-3 border border-dark-600 bg-dark-900/60 rounded overflow-hidden">
      <div className="px-3 py-2 border-b border-dark-600 text-[10px] uppercase font-mono tracking-widest text-dark-300 flex items-center justify-between gap-3">
        <span>{checked ? record.record_type + " · " + record.fqdn : "Create this record"}</span>
        {checked && (
          <span className={record.present ? "text-rust-400" : "text-warn-400"}>
            {record.present ? "published" : "missing"}
          </span>
        )}
      </div>
      {record.purpose && (
        <p className="px-3 py-2 text-[11px] text-dark-200 border-b border-dark-600">{record.purpose}</p>
      )}
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

/**
 * Render whichever fix the backend supplied.
 *
 * Dispatching on `kind` rather than on the check's `key` is what keeps this
 * component free of per-vertical knowledge: a new check that reuses an existing
 * shape needs no change here at all.
 */
function RemediationView({
  remediation,
  onApply,
}: {
  remediation: Remediation;
  /** Fill a form field with a suggested value, when the caller can. */
  onApply?: (appliesTo: string, value: string) => void;
}) {
  switch (remediation.kind) {
    case "dns_record":
      return <DnsRecordCard record={remediation.record} />;

    case "dns_records":
      return (
        <div>
          {remediation.records.map((r) => (
            <DnsRecordCard key={`${r.record_type}:${r.fqdn}`} record={r} />
          ))}
        </div>
      );

    case "value":
      return (
        <div className="mt-3 flex items-center gap-2 flex-wrap">
          <span className="text-[11px] text-dark-300">{remediation.label}:</span>
          <span className="text-xs font-mono text-dark-50 break-all">{remediation.value}</span>
          {onApply ? (
            <button
              type="button"
              onClick={() => onApply(remediation.applies_to, remediation.value)}
              className="px-2 py-0.5 bg-dark-700 text-dark-100 rounded text-[10px] font-medium hover:bg-dark-600 transition-colors"
            >
              Use it
            </button>
          ) : (
            <CopyButton value={remediation.value} label={remediation.label.toLowerCase()} />
          )}
        </div>
      );

    case "link":
      return (
        <a
          href={remediation.href}
          className="mt-3 inline-block px-3 py-1 bg-dark-700 text-dark-100 rounded text-xs font-medium hover:bg-dark-600 transition-colors"
        >
          {remediation.label}
        </a>
      );
  }
}

interface CalloutProps {
  prereq: PrereqResult | null;
  /** Re-run the check. Renders a "Check again" button when provided. */
  onRecheck?: () => void;
  checking?: boolean;
  /** Show a quiet confirmation when the prerequisite is met. Off by default. */
  showSatisfied?: boolean;
  /** Apply a suggested value to a form field, for `value` remediations. */
  onApply?: (appliesTo: string, value: string) => void;
  className?: string;
}

export function PrereqCallout({
  prereq,
  onRecheck,
  checking,
  showSatisfied = false,
  onApply,
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

      {prereq.remediation && (
        <RemediationView remediation={prereq.remediation} onApply={onApply} />
      )}

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

/**
 * Run any endpoint that returns `{ checks: PrereqResult[] }`.
 *
 * The multi-result sibling of `useDnsPrereq`, with the same two properties that
 * matter: debounced, because the app deploy form calls it on every keystroke,
 * and cancel-aware via a request sequence, so a slow lookup for a half-filled
 * form can never overwrite the verdict for the finished one.
 *
 * `path` of `null` disables the hook entirely — what a closed dialog wants.
 */
export function usePrereqs(path: string | null, opts?: { debounceMs?: number; autoPoll?: boolean }) {
  const { debounceMs = 500, autoPoll = false } = opts ?? {};
  const [checks, setChecks] = useState<PrereqResult[]>([]);
  const [checking, setChecking] = useState(false);
  const requestSeq = useRef(0);

  const run = useCallback(async (target: string | null) => {
    if (!target) {
      setChecks([]);
      return;
    }
    const seq = ++requestSeq.current;
    setChecking(true);
    try {
      const r = await api.get<{ checks: PrereqResult[] }>(target);
      if (seq === requestSeq.current) setChecks(r.checks ?? []);
    } catch {
      // Same rule as the DNS hook: an unavailable check is not a failed
      // prerequisite, and must never gate anything.
      if (seq === requestSeq.current) setChecks([]);
    } finally {
      if (seq === requestSeq.current) setChecking(false);
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => run(path), debounceMs);
    return () => clearTimeout(t);
  }, [path, debounceMs, run]);

  useEffect(() => {
    if (!autoPoll || !path || checks.length === 0) return;
    if (checks.every((c) => c.state === "satisfied")) return;
    const t = setInterval(() => run(path), 20000);
    return () => clearInterval(t);
  }, [autoPoll, path, checks, run]);

  return { checks, checking, blocker: firstBlocker(checks), recheck: () => run(path) };
}

/**
 * Render a set of prerequisites, loudest first.
 *
 * Only actionable results are shown by default. A surface with four checks would
 * otherwise print four paragraphs of "this is fine" — which buries the one that
 * isn't, and is the same mistake as rendering an error 1400 lines from its
 * button.
 */
export function PrereqList({
  checks,
  onRecheck,
  checking,
  onApply,
  showSatisfied = false,
  className = "",
}: {
  checks: PrereqResult[];
  onRecheck?: () => void;
  checking?: boolean;
  onApply?: (appliesTo: string, value: string) => void;
  showSatisfied?: boolean;
  className?: string;
}) {
  const rank = (p: PrereqResult) =>
    prereqBlocks(p) ? 0 : p.state === "unsatisfied" ? 1 : p.state === "unknown" ? 2 : 3;

  const visible = checks
    .filter((c) => showSatisfied || c.state === "unsatisfied")
    .sort((a, b) => rank(a) - rank(b));

  if (visible.length === 0) return null;

  return (
    <div className={`space-y-2 ${className}`}>
      {visible.map((c, i) => (
        <PrereqCallout
          key={c.key}
          prereq={c}
          showSatisfied={showSatisfied}
          onApply={onApply}
          // One "Check again" per list, on the most urgent item only.
          onRecheck={i === 0 ? onRecheck : undefined}
          checking={checking}
        />
      ))}
    </div>
  );
}
