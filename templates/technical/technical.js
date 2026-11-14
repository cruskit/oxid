// Progressive enhancement for the page of the `technical` experience: choosing
// another customer swaps in that customer's claims without a round trip, the
// JSON is checked as it is typed, and the redirect is previewed.
//
// Written in plain ES5 so that it also runs in the conformance suite's
// scripted browser. It is served inline, under a per-response nonce.
(function () {
  var dataEl = document.getElementById('oxid-data');
  if (!dataEl) { return; }
  var data = JSON.parse(dataEl.textContent);
  function el(id) { return document.getElementById(id); }
  var customer = el('customer'), claims = el('id_token'), base = el('base');
  var baseCustomer = el('base_customer'), status = el('json-status');
  var edited = el('edited'), reset = el('reset'), send = el('send');
  var error = el('error'), description = el('error_description');
  var success = el('outcome-success'), failure = el('outcome-error');
  var redirect = el('redirect-preview'), notice = el('script-notice');
  var remembered = el('remembered');

  function validJson() {
    try {
      var value = JSON.parse(claims.value);
      return value !== null && typeof value === 'object' && !(value instanceof Array);
    } catch (e) { return false; }
  }
  function same(a, b) {
    try { return JSON.stringify(JSON.parse(a)) === JSON.stringify(JSON.parse(b)); }
    catch (e) { return false; }
  }
  function refresh() {
    var ok = validJson();
    var isSuccess = success.checked;
    status.textContent = ok ? 'Valid JSON' : 'Not a valid JSON object';
    status.className = ok ? 'ok' : 'bad';
    edited.hidden = !ok || same(claims.value, base.value);
    send.disabled = isSuccess && !ok;
    send.textContent = isSuccess ? 'Send response' : 'Send error';
    var lines = [data.redirect_uri];
    if (isSuccess) {
      lines.push('  ?code=(generated when you send)');
    } else {
      lines.push('  ?error=' + error.value);
      lines.push('  &error_description=' + (description.value || data.errors[error.value] || ''));
    }
    if (data.state !== null) { lines.push('  &state=' + data.state); }
    lines.push('  &iss=' + data.issuer);
    redirect.textContent = lines.join('\n');
  }
  function showAttributes() {
    var blocks = document.querySelectorAll('.attributes');
    for (var i = 0; i < blocks.length; i++) {
      blocks[i].hidden = blocks[i].getAttribute('data-customer') !== customer.value;
    }
    if (remembered) { remembered.hidden = customer.value !== data.remembered; }
  }
  function loadCustomer(replacedEdits) {
    var text = data.previews[customer.value];
    if (typeof text !== 'string') { return; }
    claims.value = text;
    base.value = text;
    baseCustomer.value = customer.value;
    notice.hidden = !replacedEdits;
  }

  customer.addEventListener('change', function () {
    var hadEdits = validJson() ? !same(claims.value, base.value) : true;
    loadCustomer(hadEdits);
    showAttributes();
    refresh();
  });
  reset.addEventListener('click', function () {
    claims.value = base.value;
    notice.hidden = true;
    refresh();
  });
  error.addEventListener('change', function () {
    description.value = data.errors[error.value] || '';
    refresh();
  });
  claims.addEventListener('input', refresh);
  description.addEventListener('input', refresh);
  success.addEventListener('change', refresh);
  failure.addEventListener('change', refresh);

  reset.hidden = false;
  showAttributes();
  refresh();
})();
