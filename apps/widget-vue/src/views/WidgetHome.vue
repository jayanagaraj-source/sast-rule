<template>
  <main class="cf-home">
    <!-- CASE: R12-FP-07 -->
    <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: static constant LEGAL_HTML in this file | sink: v-html binding | trusted static markup -->
    <p class="cf-legal" v-html="legalHtml"></p>
    <!-- CASE: R12-TP-06 -->
    <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: GET /widget/announcement (tenant-editable announcement HTML) | sink: v-html binding on a multi-line tag | API content rendered raw -->
    <div
      class="cf-announcement"
      v-html="announcement"
    ></div>
    <CommentThread v-if="caseId" :case-id="caseId" />
  </main>
</template>

<script>
import { ref, onMounted } from 'vue';
import CommentThread from '../components/CommentThread.vue';
import { widgetApi } from '../composables/widget-api';

const LEGAL_HTML = 'By chatting you accept our <a href="https://caseflow.example/terms" target="_blank" rel="noopener">terms</a>.';

// Fallback template string kept for the no-build embed snippet.
// CASE: R12-KFP-03
// todook: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: n/a | sink: JS string literal | text inside a string, never compiled as a Vue template
const EMBED_FALLBACK = '<div class="cf-announcement" v-html="announcement"></div>';

export default {
  components: { CommentThread },
  props: { caseId: { type: String, default: '' } },
  setup() {
    const announcement = ref('');
    onMounted(async () => {
      announcement.value = (await widgetApi.get('/widget/announcement')).data.html;
    });
    return { announcement, legalHtml: LEGAL_HTML, embedFallback: EMBED_FALLBACK };
  },
};
</script>
