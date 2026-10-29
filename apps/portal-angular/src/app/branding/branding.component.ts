import { Component, Input } from '@angular/core';

export interface TenantBranding {
  logoUrl: string;
  primaryColor: string;
  portalTitle: string;
}

@Component({
  selector: 'cf-branding',
  templateUrl: './branding.component.html',
})
export class BrandingComponent {
  @Input() branding: TenantBranding = { logoUrl: '/assets/caseflow.svg', primaryColor: '#3b5bdb', portalTitle: 'Support' };
}
