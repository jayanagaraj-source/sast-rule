import React, { useState } from 'react';
import axios from 'axios';

const DEFAULT_SETTINGS = { locale: 'en-GB', density: 'comfortable', shortcuts: true };

export default function Settings({ tenantId }) {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [status, setStatus] = useState('');

  async function importSettings(file) {
    // Admins share settings files with each other via the community forum.
    const imported = JSON.parse(await file.text());
    // CASE: R08-TP-16
    // ruleid: JS-002 | src: uploaded settings file (JSON.parse) | sink: Object.assign on React state | target-object prototype mutation: a "__proto__" key replaces the state object's prototype, and the shared state object is mutated in place
    setSettings(Object.assign(settings, imported));
  }

  function toggle(key) {
    // CASE: R08-FP-24, R07-FP-14
    // ok: JS-002, gitlab.eslint.detect-object-injection | src: own UI toggle (fixed checkbox keys) | sink: React state update | fixed-key spread into a new object
    setSettings({ ...settings, [key]: !settings[key] });
  }

  async function save() {
    // CASE: R06-TP-07
    // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.put | settings (including the tenant id) sent over HTTP (JSX)
    await axios.put("http://settings.caseflow.example/tenants/" + tenantId, settings);
    setStatus('saved');
  }

  async function ping() {
    // CASE: R06-FP-10
    // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | HTTPS
    const r = await fetch("https://api.caseflow.example/health");
    setStatus(r.ok ? 'online' : 'degraded');
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); save(); }}>
      <input type="file" accept="application/json" onChange={(e) => importSettings(e.target.files[0])} />
      <label>
        <input type="checkbox" checked={settings.shortcuts} onChange={() => toggle('shortcuts')} /> Keyboard shortcuts
      </label>
      <button type="submit">Save</button>
      <button type="button" onClick={ping}>Check API</button>
      <p role="status">{status}</p>
    </form>
  );
}
