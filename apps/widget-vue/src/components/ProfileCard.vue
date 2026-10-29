<template>
  <div class="cf-profile">
    <h3>{{ name }}</h3>
    <!-- CASE: R12-TP-04 -->
    <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: untrusted prop bioHtml (requester profile from the host page) | sink: v-html binding | prop content controlled by whoever embeds or edits the profile -->
    <section class="cf-bio" v-html="bioHtml"></section>
    <!-- CASE: R12-FP-06 -->
    <!-- ok: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: prop bioSanitizedHtml (sanitised server-side with sanitize-html at write time) | sink: v-html binding | backend-sanitised HTML -->
    <section class="cf-bio" v-html="bioSanitizedHtml"></section>
    <!-- CASE: R12-TP-05 -->
    <!-- ruleid: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html | src: search term + requester name | sink: v-html binding through a helper | highlight() wraps matches in mark tags but never escapes the text -->
    <p class="cf-match" v-html="highlight(name, searchTerm)"></p>
    <div ref="signatureEl" class="cf-signature"></div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref, h, type PropType } from 'vue';

export default defineComponent({
  name: 'ProfileCard',
  props: {
    name: { type: String, required: true },
    bioHtml: { type: String, default: '' },
    bioSanitizedHtml: { type: String, default: '' },
    searchTerm: { type: String, default: '' },
    signatureHtml: { type: String as PropType<string>, default: '' },
  },
  setup(props) {
    const signatureEl = ref<HTMLDivElement | null>(null);

    function highlight(text: string, term: string): string {
      if (!term) return text;
      return text.split(term).join(`<mark>${term}</mark>`);
    }

    onMounted(() => {
      // Alternative XSS sink (innerHTML through a template ref), outside the 13 benchmark rules: see README "Alternative sinks".
      signatureEl.value!.innerHTML = props.signatureHtml;
    });

    return { signatureEl, highlight };
  },
});

// Render-function variant used by the compact layout.
export const CompactBio = defineComponent({
  props: { bioHtml: { type: String, default: '' } },
  setup(props) {
    // Alternative XSS sink (render function innerHTML), outside the 13 benchmark rules: see README "Alternative sinks".
    return () => h('div', { class: 'cf-bio-compact', innerHTML: props.bioHtml });
  },
});
</script>
