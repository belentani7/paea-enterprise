'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(
  path.join(__dirname, '..', 'web', 'dashboard', 'index.html'), 'utf8'
);
const script = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/)?.[1];
assert.ok(script, 'The dashboard must include its application script');

function dashboard() {
  const elements = new Map();
  let networkRequests = 0;
  const document = {
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          innerHTML: '', textContent: '', className: '', value: '',
          style: {}, classList: { add() {}, remove() {} },
          addEventListener() {},
        });
      }
      return elements.get(id);
    },
  };
  const context = {
    document, Headers, console,
    fetch: () => { networkRequests++; throw Error('Unexpected request'); },
    setTimeout: () => 1, clearTimeout() {}, setInterval() {},
  };
  vm.runInNewContext(
    script + '\n;globalThis.__dashboardTest = { renderTasks, renderLearnings, renderStatus, badge };',
    context, { timeout: 1000 }
  );
  return {
    ...context.__dashboardTest,
    element: id => document.getElementById(id),
    networkRequests: () => networkRequests,
  };
}

const payload = '<img src=x onerror=alert(1)>';

test('renders untrusted task fields as text, not HTML', () => {
  const app = dashboard();
  app.renderTasks([{ id: payload, input: payload, status: payload, agent: payload, at: payload }]);
  const markup = app.element('tasksBody').innerHTML;
  assert.doesNotMatch(markup, /<img\b/i);
  assert.match(markup, /&lt;img/);
  assert.match(markup, /badge b-unknown/);
  assert.doesNotMatch(markup, /onerror=alert\(1\)>/);
});

test('renders learning text and numeric fields safely', () => {
  const app = dashboard();
  app.renderLearnings([{ pattern: payload, fix: payload, success: payload, failures: payload }]);
  const markup = app.element('learningsBody').innerHTML;
  assert.doesNotMatch(markup, /<img\b/i);
  assert.equal((markup.match(/&lt;img/g) || []).length, 4);
});

test('escapes KPI values without losing valid status styles', () => {
  const app = dashboard();
  app.renderStatus({ tasks: { total: payload }, learnings: payload, audit_chain: 'valid' });
  assert.doesNotMatch(app.element('kpis').innerHTML, /<img\b/i);
  assert.match(app.element('kpis').innerHTML, /&lt;img/);
  assert.match(app.badge('completed'), /badge b-completed/);
  assert.match(app.badge('completed" onclick="evil()'), /badge b-unknown/);
  assert.doesNotMatch(app.badge('completed" onclick="evil()'), /onclick="evil\(\)"/);
});

test('does not poll private APIs before a token is provided', () => {
  const app = dashboard();
  assert.equal(app.networkRequests(), 0);
  assert.equal(app.element('healthPill').textContent, 'SIN CONEXIÓN');
});

test('empty task and learning lists retain helpful states', () => {
  const app = dashboard();
  app.renderTasks([]);
  app.renderLearnings([]);
  assert.match(app.element('tasksBody').innerHTML, /Aún no hay tareas/);
  assert.match(app.element('learningsBody').innerHTML, /Aún no hay patrones/);
});
