package com.caseflow.billing.search;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

/** Invoice search for the billing console. Patterns come from the agent's search box or saved filters. */
@Service
public class InvoiceSearchService {

    private static final int MAX_QUERY_LENGTH = 100;
    // CASE: R11-FP-13
    // ok: SAST-011 | src: static | sink: Pattern.compile | static linear pattern compiled once
    private static final Pattern INVOICE_NUMBER = Pattern.compile("^INV-\\d{4}-\\d{6}$");
    // Nested quantifier: catastrophic on long runs of word characters followed by a mismatch.
    private static final Pattern LEGACY_REFERENCE = Pattern.compile("^([A-Za-z0-9]+\\s?)+$");

    private final InvoiceRepository repository;

    public InvoiceSearchService(InvoiceRepository repository) {
        this.repository = repository;
    }

    public List<Invoice> searchByMemo(String tenantId, String userPattern) {
        // CASE: R11-GAP-03
        // todoruleid: SAST-011 | src: request param q (InvoiceController) | sink: Pattern.compile | attacker regex; the rule's patterns are new RegExp / re.compile, which do not exist in Java
        Pattern p = Pattern.compile(userPattern);
        return repository.findByTenant(tenantId).stream()
                .filter(inv -> p.matcher(inv.memo()).find())
                .collect(Collectors.toList());
    }

    public List<Invoice> searchByCustomer(String tenantId, String userRegex) {
        // CASE: R11-GAP-04
        // todoruleid: SAST-011 | src: saved filter (user-defined) | sink: String.matches | String.matches compiles the user regex on every call
        return repository.findByTenant(tenantId).stream()
                .filter(inv -> inv.customerName().matches(userRegex))
                .collect(Collectors.toList());
    }

    public boolean isLegacyReference(String reference) {
        // CASE: R11-GAP-05
        // todoruleid: SAST-011 | src: request body field reference | sink: static nested-quantifier Pattern | exponential backtracking on unbounded request input
        return LEGACY_REFERENCE.matcher(reference).matches();
    }

    public List<Invoice> searchByMemoLiteral(String tenantId, String term) {
        String bounded = term.length() > MAX_QUERY_LENGTH ? term.substring(0, MAX_QUERY_LENGTH) : term;
        // CASE: R11-FP-14
        // ok: SAST-011 | src: request param q (quoted) | sink: Pattern.compile | Pattern.quote makes the input literal
        Pattern p = Pattern.compile(Pattern.quote(bounded), Pattern.CASE_INSENSITIVE);
        return repository.findByTenant(tenantId).stream()
                .filter(inv -> p.matcher(inv.memo()).find())
                .collect(Collectors.toList());
    }

    public boolean isInvoiceNumber(String value) {
        // CASE: R11-FP-15
        // ok: SAST-011 | src: request param | sink: static linear Pattern | anchored, no nested quantifiers
        return INVOICE_NUMBER.matcher(value).matches();
    }
}
