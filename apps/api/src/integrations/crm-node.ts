// CRM connector, modelled on workflow-automation "nodes": each operation reads its parameters from the node
// configuration that a tenant admin saved in the automation builder, then calls the CRM REST API.
import { createPartnerClient } from '../lib/http-client';

export interface NodeParameters {
  resource: 'contact' | 'deal';
  operation: 'create' | 'update';
  email?: string;
  contactId?: string;
  additionalFields?: Record<string, string | number | boolean>;
  updateFields?: Record<string, string | number | boolean>;
}

export interface ExecutionItem {
  json: Record<string, unknown>;
}

const CRM_FIELD_WHITELIST = new Set(['firstname', 'lastname', 'company', 'phone', 'lifecyclestage']);

export class CrmNode {
  constructor(private readonly params: NodeParameters, private readonly token: string) {}

  async execute(items: ExecutionItem[]): Promise<ExecutionItem[]> {
    const client = createPartnerClient('https://api.crm.example/crm/v3', this.token);
    const out: ExecutionItem[] = [];

    for (const item of items) {
      if (this.params.operation === 'create') {
        const body: Record<string, unknown> = { email: this.params.email };
        const additionalFields = this.params.additionalFields ?? {};
        // CASE: R08-FP-03
        // ok: JS-002 | src: node settings saved by the tenant admin | sink: Object.assign | integration-owned connector fields shaping the outbound CRM request; nothing local is mutated
        Object.assign(body, additionalFields);
        const { data } = await client.post('/objects/contacts', { properties: body });
        out.push({ json: data });
      } else {
        const body: Record<string, unknown> = {};
        const updateFields = this.params.updateFields ?? {};
        // CASE: R08-FP-04
        // ok: JS-002 | src: node settings | sink: Object.assign | outbound request body built from node configuration
        Object.assign(body, updateFields);
        const { data } = await client.patch(`/objects/contacts/${encodeURIComponent(this.params.contactId!)}`, { properties: body });
        out.push({ json: data });
      }
      // CASE: R08-FP-05
      // ok: JS-002 | src: previous node output | sink: Object.assign onto a fresh literal (3 args) | item copy into a new object
      out.push({ json: Object.assign({}, item.json, { _source: 'crm' }) });
    }
    return out;
  }

  /** Maps a CRM contact (third-party response) onto our local contact row. */
  mapContact(local: Record<string, unknown>, remote: { properties: Record<string, unknown> }): Record<string, unknown> {
    const picked: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(remote.properties)) if (CRM_FIELD_WHITELIST.has(k)) picked[k] = v;
    // CASE: R08-FP-06
    // ok: JS-002 | src: third-party response (allowlisted) | sink: Object.assign | only whitelisted CRM properties copied
    return Object.assign(local, picked);
  }

  /** Older sync path, still used for "deal" resources. */
  mapDealUnfiltered(local: Record<string, unknown>, remote: { properties: Record<string, unknown> }): Record<string, unknown> {
    // CASE: R08-AMB-01
    // tg-either: JS-002 | src: third-party CRM response | sink: Object.assign | every remote property lands on the local row; exploitable only if the CRM account is compromised
    return Object.assign(local, remote.properties);
  }
}
