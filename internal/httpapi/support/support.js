'use strict';
(() => {
  const element = id => document.getElementById(id);
  const form = element('report');
  if (!form) return;
  // Keep one capability per attempted request. An uncertain response can be
  // retried idempotently; changing the body after submission requires a new ID.
  let pending;
  let submitted = false;
  async function responseBody(response) {
    let body;
    try { body = await response.json(); } catch { throw new Error('Could not read the server response. Save your receipt and retry.'); }
    if (!response.ok) throw new Error(body.error?.message || 'Request failed. Please retry or use the contact email.');
    return body;
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (submitted) return;
    const button = element('submit');
    button.disabled = true;
    try {
      if (!pending) {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        const secret = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        pending = {id: crypto.randomUUID(), secret, body: {
          access_token: secret, category: element('category').value, contact: element('contact').value,
          content_reference: element('reference').value, details: element('details').value,
          signature: element('signature').value, good_faith: element('goodFaith').checked,
          authorized: element('authorized').checked
        }};
      }
      element('receipt').hidden = false;
      element('receiptText').value = `Case ID: ${pending.id}\nReceipt secret: ${pending.secret}\nKeep this private. A receipt is submitted only after the server confirms it below.`;
      const response = await fetch(`/v1/support/cases/${pending.id}`, {
        method: 'PUT', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(pending.body)
      });
      const status = await responseBody(response);
      element('result').textContent = `Received by the server: ${status.received_at}. Case ${status.id}. Status: ${status.status}. Save the private receipt below. This does not confirm that a notice is valid or that content has been removed.`;
      submitted = true;
      button.textContent = 'Request received';
      form.querySelectorAll('input,textarea,select').forEach(field => { field.disabled = true; });
    } catch (error) {
      element('result').textContent = `${error.message} If you retry, the original request will be sent again. Reload to prepare a different request.`;
    } finally { if (!submitted) button.disabled = false; }
  });
  element('lookup').addEventListener('submit', async event => {
    event.preventDefault();
    const id = element('caseID').value.trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      element('status').textContent = 'Enter a valid case ID.'; return;
    }
    try {
      const response = await fetch(`/v1/support/cases/${id}`, {cache: 'no-store', credentials: 'omit',
        referrerPolicy: 'no-referrer', headers: {Authorization: `Bearer ${element('caseSecret').value.trim()}`}});
      const result = await responseBody(response);
      element('status').textContent = `Status: ${result.status}. Updated: ${result.updated_at}. ${result.public_update || ''}`;
    } catch (error) { element('status').textContent = error.message; }
  });
})();
