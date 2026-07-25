import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { FIELD_GUIDANCE, type FieldGuidanceId } from "../content/guidance.generated";

// The passive tier of the guidance layer.
//
// `Prerequisite.tsx` renders the two loud tiers — the amber callout and the red
// gate — from PrereqResults the backend computes. This renders the quiet one:
// the line under a field, and the longer explanation behind its (i).
//
// The three are one content system, not three (brief §3.9). Every string here
// comes from `content/guidance.generated.ts`, which is emitted from the same
// Rust registry the callouts are rendered from, so a field's calm explanation
// and the loud version of the same concern cannot describe different products.
// That file is generated — edit `services/prerequisites/copy.rs` instead, and a
// backend test will fail until it is regenerated.

/**
 * The line under a form field, plus an (i) when there is more worth saying.
 *
 * `id` is checked against the generated registry at compile time: a typo, or a
 * field whose entry was removed, is a type error rather than a silently blank
 * hint.
 */
export function FieldHelp({ id, className = "" }: { id: FieldGuidanceId; className?: string }) {
  const guidance = FIELD_GUIDANCE[id];

  // A tooltip-only entry: the standing line for this field is computed from the
  // form's own state, so the component renders it and this renders nothing.
  // Reach for `<InfoTip>` directly in that case.
  if (!guidance.help) return null;

  return (
    <p className={`text-xs text-dark-400 mt-1.5 ${className}`}>
      {guidance.help}
      {guidance.more && <InfoTip id={id} />}
    </p>
  );
}

/**
 * The (i) itself, for the cases where a field's label needs it but its helper
 * line is rendered by something else.
 *
 * Click, not hover. Hover tooltips are unreachable on a touch screen and
 * unreadable to anyone who needs more than a second with the text — and this
 * content exists precisely for the person who is not sure.
 */
export function InfoTip({ id, className = "" }: { id: FieldGuidanceId; className?: string }) {
  const guidance = FIELD_GUIDANCE[id];
  const [open, setOpen] = useState(false);
  const [alignRight, setAlignRight] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const panelId = useId();

  // Flip the panel to the right edge when opening it left-aligned would run it
  // off the viewport.
  //
  // Several of these (i)s sit on the right-hand column of a two-column form or
  // inside a narrow modal, where a fixed left-aligned 18rem panel is simply cut
  // off — help text the user cannot finish reading is the same defect as help
  // text that isn't there. Measured on open rather than guessed from the layout,
  // because the same component is used in both columns.
  useLayoutEffect(() => {
    if (!open || !wrapRef.current) return;
    const { left } = wrapRef.current.getBoundingClientRect();
    const PANEL_WIDTH = 288; // w-72
    const MARGIN = 16;
    setAlignRight(left + PANEL_WIDTH + MARGIN > window.innerWidth);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!guidance.more) return null;

  return (
    <span ref={wrapRef} className={`relative inline-block align-middle ml-1.5 ${className}`}>
      <button
        type="button"
        aria-label={`More about ${guidance.label}`}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={() => setOpen((v) => !v)}
        // `normal-case` because several call sites sit inside uppercase
        // headings, where the glyph would otherwise render as a bare "I".
        className="w-4 h-4 rounded-full border border-dark-500 text-dark-300 text-[10px] leading-none font-medium normal-case hover:border-dark-400 hover:text-dark-100 transition-colors"
      >
        i
      </button>
      {open && (
        <span
          id={panelId}
          role="note"
          className={`absolute ${alignRight ? "right-0" : "left-0"} top-6 z-20 w-72 max-w-[calc(100vw-2rem)] p-3 rounded border border-dark-600 bg-dark-900 shadow-lg text-xs text-dark-100 font-normal normal-case tracking-normal`}
        >
          {guidance.more}
        </span>
      )}
    </span>
  );
}
