import { Component, Input, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface PortalCase {
  id: string;
  subject: string;
  status: string;
  portalLink: string;
  descriptionHtml: string;
  requester: { name: string; avatarUrl: string };
  assignee?: { name: string; avatarUrl: string };
}

@Component({
  selector: 'cf-case-detail',
  templateUrl: './case-detail.component.html',
})
export class CaseDetailComponent implements OnInit {
  @Input() caseId!: string;
  case$!: Observable<PortalCase>;

  constructor(private readonly http: HttpClient) {}

  ngOnInit(): void {
    this.case$ = this.http.get<PortalCase>(`/portal/api/cases/${encodeURIComponent(this.caseId)}`);
  }

  satisfaction(score: 1 | 2 | 3 | 4 | 5): Observable<void> {
    // CASE: R06-GAP-01
    // todoruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: Angular HttpClient.post | CSAT score posted over plaintext HTTP; the rule only knows axios and fetch
    return this.http.post<void>('http://csat.caseflow.example/v1/responses', { caseId: this.caseId, score });
  }

  async attachmentsCount(): Promise<number> {
    // CASE: R06-FP-01
    // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | HTTPS
    const r = await fetch("https://portal.caseflow.example/api/attachments/count?case=" + encodeURIComponent(this.caseId));
    return (await r.json()).count;
  }
}
