using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Caseflow.Reports.Services;

/// <summary>Filters report rows with patterns typed into the report builder.</summary>
public sealed class ReportFilterService
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(200);

    // CASE: R11-FP-21
    // ok: SAST-011 | src: static | sink: Regex (compiled) | static linear pattern
    private static readonly Regex CaseNumber = new Regex(@"^CF-\d{1,9}$", RegexOptions.Compiled);

    public IEnumerable<string> FilterSubjects(IEnumerable<string> subjects, string userPattern)
    {
        // CASE: R11-GAP-11
        // todoruleid: SAST-011 | src: query string pattern (ReportsController) | sink: new Regex | attacker regex with no timeout; C# Regex is not RegExp, so the rule cannot match
        var regex = new Regex(userPattern);
        return subjects.Where(s => regex.IsMatch(s));
    }

    public bool MatchesRequester(string requester, string userPattern)
    {
        // CASE: R11-GAP-12
        // todoruleid: SAST-011 | src: saved report filter (user-defined) | sink: Regex.IsMatch | static helper compiles the user pattern, no timeout
        return Regex.IsMatch(requester, userPattern);
    }

    public IEnumerable<string> FilterSubjectsLiteral(IEnumerable<string> subjects, string term)
    {
        // CASE: R11-FP-22
        // ok: SAST-011 | src: query string term (escaped) | sink: new Regex | Regex.Escape makes the input literal
        var regex = new Regex(Regex.Escape(term), RegexOptions.IgnoreCase, MatchTimeout);
        return subjects.Where(s => regex.IsMatch(s));
    }

    public IEnumerable<string> FilterSubjectsSafeEngine(IEnumerable<string> subjects, string userPattern)
    {
        // CASE: R11-FP-23
        // ok: SAST-011 | src: query string pattern | sink: new Regex with NonBacktracking | .NET 7 non-backtracking engine runs in linear time
        var regex = new Regex(userPattern, RegexOptions.NonBacktracking, MatchTimeout);
        return subjects.Where(s => regex.IsMatch(s));
    }

    public bool IsCaseNumber(string value) => CaseNumber.IsMatch(value);
}
