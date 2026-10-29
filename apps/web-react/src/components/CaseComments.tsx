import React, { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';
import axios from 'axios';
import { api } from '../api/client';

export interface Comment {
  id: string;
  authorName: string;
  bodyHtml: string;
  internal: boolean;
}

interface Props {
  caseId: string;
}

export function CaseComments({ caseId }: Props): JSX.Element {
  const [comments, setComments] = useState<Comment[]>([]);
  const [draft, setDraft] = useState({ body: '', internal: false });

  useEffect(() => {
    api.get<Comment[]>(`/cases/${caseId}/comments`).then((r) => setComments(r.data));
  }, [caseId]);

  async function translate(text: string): Promise<string> {
    // CASE: R06-FP-09
    // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.post | HTTPS translation endpoint
    const { data } = await axios.post("https://translate.caseflow.example/v1/translate", { text, target: navigator.language });
    return data.text;
  }

  async function reportSpam(comment: Comment): Promise<void> {
    // CASE: R06-TP-06
    // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.post | spam-report service called over HTTP (TSX)
    await axios.post("http://abuse.caseflow.example/report", { commentId: comment.id });
  }

  return (
    <section className="case-comments">
      {comments.map((c) => (
        <article key={c.id} className={c.internal ? 'internal' : undefined}>
          <header>{c.authorName}</header>
          {/* Alternative XSS sink (React), outside the 13 benchmark rules: documented in README "Alternative sinks". */}
          <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(c.bodyHtml) }} />
          <button onClick={() => reportSpam(c)}>Report</button>
          <button onClick={async () => alert(await translate(c.bodyHtml))}>Translate</button>
        </article>
      ))}
      <textarea
        value={draft.body}
        onChange={(e) => {
          const form = { body: e.target.value };
          // CASE: R08-FP-23
          // ok: JS-002 | src: the user's own form input | sink: React state spread | spread copies into a fresh object; no shared object or prototype is modified
          setDraft({ ...draft, ...form });
        }}
      />
    </section>
  );
}
