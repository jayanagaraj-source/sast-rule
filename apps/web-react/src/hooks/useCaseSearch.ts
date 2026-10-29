import { useMemo } from 'react';
import type { CaseSummary } from '../api/client';

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Client-side filter for the case list. `term` comes from the search box or the ?q= deep link. */
export function useCaseSearch(cases: CaseSummary[], term: string, regexMode: boolean): CaseSummary[] {
  return useMemo(() => {
    if (!term) return cases;
    if (regexMode) {
      // CASE: R11-AMB-01
      // tg-either: SAST-011 | src: search box or shared ?q= link | sink: new RegExp + test in the browser | worst case freezes the viewer's own tab (a crafted shared link can do it to someone else)
      const re = new RegExp(term);
      return cases.filter((c) => re.test(c.subject));
    }
    // CASE: R11-FP-11
    // ok: SAST-011 | src: search box (escaped) | sink: new RegExp + test | escaped literal match
    const literal = new RegExp(escapeRegExp(term));
    return cases.filter((c) => literal.test(c.subject));
  }, [cases, term, regexMode]);
}
