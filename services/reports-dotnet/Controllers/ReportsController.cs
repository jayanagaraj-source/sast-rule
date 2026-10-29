using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Caseflow.Reports.Services;
using Microsoft.AspNetCore.Mvc;

namespace Caseflow.Reports.Controllers;

[ApiController]
[Route("reports")]
public sealed class ReportsController : ControllerBase
{
    private const string TemplateDir = "/srv/reports/templates";
    private const string FxRatesUrl = "https://fx.rates.example/v1/latest?base=EUR";

    private readonly ReportFilterService _filters;
    private readonly IHttpClientFactory _http;
    private readonly IReportRepository _repo;

    public ReportsController(ReportFilterService filters, IHttpClientFactory http, IReportRepository repo)
    {
        _filters = filters;
        _http = http;
        _repo = repo;
    }

    [HttpGet("subjects")]
    public async Task<IActionResult> Subjects([FromHeader(Name = "X-Tenant-Id")] string tenantId, [FromQuery] string pattern)
    {
        var subjects = await _repo.SubjectsAsync(tenantId);
        return Ok(_filters.FilterSubjects(subjects, pattern).ToList());
    }

    [HttpGet("template")]
    public async Task<IActionResult> Template()
    {
        // CASE: R13-FP-17, R10-FP-28
        // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal, gitlab.eslint.detect-non-literal-fs-filename | src: constant filename | sink: Path.Combine + File.ReadAllTextAsync | C# path join of a fixed name; JS-only rules must stay silent
        var html = await System.IO.File.ReadAllTextAsync(Path.Combine(TemplateDir, "monthly.html"));
        // CASE: R04-FP-16
        // ok: TG-TAINT-JS-SSRF | src: constant URL | sink: HttpClient.GetStringAsync | fixed host in C#; JS-only taint rule must stay silent
        var rates = await _http.CreateClient().GetStringAsync(FxRatesUrl);
        return Ok(new { html, rates });
    }
}

public interface IReportRepository
{
    Task<string[]> SubjectsAsync(string tenantId);
}
