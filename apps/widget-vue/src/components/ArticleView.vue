<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { widgetApi } from '../composables/widget-api';

interface Article {
  id: string;
  title: string;
  markdown: string;
  authoredBy: 'tenant' | 'caseflow-staff';
}

const props = defineProps<{ articleId: string; showStatusBanner?: boolean }>();
const article = ref<Article | null>(null);
const statusBanner = ref('');

// Rendered markdown, not sanitised (legacy path for articles imported from the old help centre).
const renderedRaw = computed(() => (article.value ? (marked.parse(article.value.markdown) as string) : ''));
// Same markdown, sanitised.
const renderedSafe = computed(() => (article.value ? DOMPurify.sanitize(marked.parse(article.value.markdown) as string) : ''));

onMounted(async () => {
  const { data } = await widgetApi.get<Article>(`/widget/kb/${props.articleId}`);
  article.value = data;
  if (props.showStatusBanner) {
    // Status banners are authored by Caseflow staff in the internal CMS and served from our own CDN.
    statusBanner.value = (await widgetApi.get<{ html: string }>('/widget/status-banner')).data.html;
  }
});
</script>

<template>
  <!-- CASE: R12-FP-01 -->
  <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: Caseflow-staff CMS (status banner, internal only) | sink: v-html binding | trusted CMS markup authored by our own staff -->
  <div v-if="statusBanner" class="cf-status" v-html="statusBanner"></div>
  <article v-if="article">
    <h1>{{ article.title }}</h1>
    <!-- CASE: R12-TP-01 -->
    <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: knowledge-base article written by a tenant admin, shown to every visitor of the shared widget origin | sink: v-html binding | markdown rendered without sanitising: raw HTML in markdown passes through -->
    <div v-if="article.authoredBy === 'tenant'" class="cf-md" v-html="renderedRaw"></div>
    <!-- CASE: R12-FP-02 -->
    <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: same markdown, DOMPurify-sanitised | sink: v-html binding | sanitised after rendering -->
    <div v-else class="cf-md" v-html="renderedSafe"></div>
  </article>
</template>
