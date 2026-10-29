<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

/**
 * Legacy knowledge-base search (Laravel). Still serves the classic help centre for ~300 tenants.
 */
class KnowledgeBaseController extends Controller
{
    private const MAX_TERM_LENGTH = 80;
    private const STATUS_URL = 'https://status.partner-crm.example/api/v2/status.json';
    private const DEFAULT_LAYOUT = ['columns' => 2, 'showAuthor' => true];

    public function search(Request $request): JsonResponse
    {
        $userPattern = (string) $request->query('pattern', '');
        $articles = DB::table('kb_articles')->where('tenant_id', $request->user()->tenant_id)->pluck('title');

        // CASE: R11-GAP-07
        // todoruleid: SAST-011 | src: query param pattern | sink: preg_match | attacker-supplied PCRE; SAST-011 patterns (new RegExp / re.compile) do not exist in PHP
        $matches = $articles->filter(fn (string $t) => preg_match($userPattern, $t) === 1);

        return response()->json($matches->values());
    }

    public function searchLiteral(Request $request): JsonResponse
    {
        $term = mb_substr((string) $request->query('q', ''), 0, self::MAX_TERM_LENGTH);
        // CASE: R11-FP-17
        // ok: SAST-011 | src: query param q (quoted, bounded) | sink: preg_match | preg_quote escapes delimiter and metacharacters
        $regex = '/' . preg_quote($term, '/') . '/iu';
        $articles = DB::table('kb_articles')->where('tenant_id', $request->user()->tenant_id)->pluck('title');

        return response()->json($articles->filter(fn (string $t) => preg_match($regex, $t) === 1)->values());
    }

    public function validateSlug(Request $request): JsonResponse
    {
        $slug = (string) $request->input('slug', '');
        // CASE: R11-GAP-08
        // todoruleid: SAST-011 | src: request body slug | sink: preg_match with nested quantifier | (a+)+-style backtracking on unbounded input
        $valid = preg_match('/^([a-z0-9]+-?)+$/', $slug) === 1;

        return response()->json(['valid' => $valid]);
    }

    public function validateLocale(Request $request): JsonResponse
    {
        // CASE: R11-FP-18
        // ok: SAST-011 | src: request body locale | sink: preg_match | static linear pattern
        return response()->json(['valid' => preg_match('/^[a-z]{2}(-[A-Z]{2})?$/', (string) $request->input('locale')) === 1]);
    }

    public function layout(Request $request): JsonResponse
    {
        // CASE: R08-FP-26
        // ok: JS-002 | src: allowlisted request fields | sink: array_merge | PHP array merge of two fixed keys; the JS-only rule must stay silent
        $layout = array_merge(self::DEFAULT_LAYOUT, $request->only(['columns', 'showAuthor']));
        // CASE: R04-FP-14
        // ok: TG-TAINT-JS-SSRF | src: constant URL | sink: Http::get | fixed host in PHP; JS-only taint rule must stay silent
        $status = Http::timeout(5)->get(self::STATUS_URL)->json();

        return response()->json(['layout' => $layout, 'status' => $status]);
    }
}
