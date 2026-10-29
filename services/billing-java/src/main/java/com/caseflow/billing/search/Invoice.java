package com.caseflow.billing.search;

import java.math.BigDecimal;
import java.time.LocalDate;

public record Invoice(String id, String tenantId, String customerName, String memo, BigDecimal total, LocalDate issuedOn) {}
