package com.caseflow.billing.search;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class InvoiceRepository {

    private final JdbcTemplate jdbc;

    public InvoiceRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Invoice> findByTenant(String tenantId) {
        return jdbc.query(
                "SELECT id, tenant_id, customer_name, memo, total, issued_on FROM invoices WHERE tenant_id = ? ORDER BY issued_on DESC LIMIT 5000",
                (rs, i) -> new Invoice(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getBigDecimal(5), rs.getDate(6).toLocalDate()),
                tenantId);
    }
}
