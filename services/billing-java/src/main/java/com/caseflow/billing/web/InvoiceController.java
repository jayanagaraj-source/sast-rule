package com.caseflow.billing.web;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import com.caseflow.billing.search.Invoice;
import com.caseflow.billing.search.InvoiceSearchService;

@RestController
@RequestMapping("/billing/invoices")
public class InvoiceController {

    private static final Path INVOICE_DIR = Paths.get("/var/lib/caseflow/invoices");
    private static final String FX_RATES_URL = "https://fx.rates.example/v1/latest?base=EUR";

    private final InvoiceSearchService search;
    private final RestTemplate http = new RestTemplate();

    public InvoiceController(InvoiceSearchService search) {
        this.search = search;
    }

    @GetMapping
    public List<Invoice> find(@RequestHeader("X-Tenant-Id") String tenantId, @RequestParam("q") String q) {
        return search.searchByMemo(tenantId, q);
    }

    @GetMapping("/literal")
    public List<Invoice> findLiteral(@RequestHeader("X-Tenant-Id") String tenantId, @RequestParam("q") String q) {
        return search.searchByMemoLiteral(tenantId, q);
    }

    @GetMapping("/{id}/pdf")
    public ResponseEntity<byte[]> pdf(@PathVariable UUID id) throws java.io.IOException {
        // CASE: R13-FP-14, R10-FP-25
        // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal, gitlab.eslint.detect-non-literal-fs-filename | src: path variable typed as UUID | sink: Paths.resolve + Files.readAllBytes | Java code with a UUID-typed id; JS-only rules must stay silent
        byte[] body = Files.readAllBytes(INVOICE_DIR.resolve(id + ".pdf"));
        return ResponseEntity.ok().header("Content-Type", "application/pdf").body(body);
    }

    @GetMapping("/fx")
    @SuppressWarnings("unchecked")
    public Map<String, Object> fx() {
        // CASE: R04-FP-11
        // ok: TG-TAINT-JS-SSRF | src: constant URL | sink: RestTemplate.getForObject | fixed host in Java; JS-only taint rule must stay silent
        return http.getForObject(FX_RATES_URL, Map.class);
    }
}
