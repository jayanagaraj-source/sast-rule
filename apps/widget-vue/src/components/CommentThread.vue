<template>
  <section class="cf-thread">
    <article v-for="comment in comments" :key="comment.id" class="cf-comment">
      <header>
        <!-- CASE: R12-FP-03 -->
        <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: author name | sink: text interpolation | mustache-style interpolation is escaped by Vue -->
        <strong>{{ comment.authorName }}</strong>
        <!-- CASE: R12-FP-04 -->
        <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: timestamp | sink: v-text directive | v-text sets textContent -->
        <time v-text="formatDate(comment.createdAt)"></time>
      </header>
      <!-- CASE: R12-TP-02 -->
      <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: GET /widget/cases/:id/comments (customer-authored HTML) | sink: v-html binding | unsanitised user comment rendered as HTML -->
      <div class="cf-body" v-html="comment.body"></div>
      <!-- CASE: R12-FP-05 -->
      <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: same comment, DOMPurify-sanitised | sink: v-html binding | sanitize() wraps DOMPurify with the default safe profile -->
      <div class="cf-body-safe" v-html="sanitize(comment.body)"></div>
      <!-- CASE: R12-KFP-01 -->
      <!-- todook: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: n/a | sink: data attribute named data-v-html | not a Vue directive, just a data attribute used by the analytics script -->
      <span class="cf-meta" data-v-html="comment-body"></span>
    </article>
    <!-- CASE: R12-KFP-02 -->
    <!-- todook: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: n/a | sink: commented-out markup | disabled template line inside an HTML comment, never rendered -->
    <!-- <div class="cf-last" v-html="lastReply"></div> -->
    <footer v-if="lastReply">
      <!-- CASE: R12-TP-03 -->
      <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: API field lastReplyHtml (agent reply, stored raw) | sink: v-html binding | API-returned HTML without sanitising -->
      <p class="cf-last" v-html="lastReply"></p>
    </footer>
  </section>
</template>

<script>
import DOMPurify from 'dompurify';
import { widgetApi } from '../composables/widget-api';

export default {
  name: 'CommentThread',
  props: {
    caseId: { type: String, required: true },
  },
  data() {
    return { comments: [], lastReply: '' };
  },
  async mounted() {
    const { data } = await widgetApi.get(`/widget/cases/${this.caseId}/comments`);
    this.comments = data.items;
    this.lastReply = data.lastReplyHtml;
  },
  methods: {
    sanitize(html) {
      return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
    },
    formatDate(iso) {
      return new Date(iso).toLocaleString();
    },
  },
};
</script>
