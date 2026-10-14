(function () {
  var $ = function (id) { return document.getElementById(id); };
  var view = 'overview', filter = 'all', logQuery = '', timer = null;
  var hist = { q: [], b: [], c: [], o: [] }, prev = null, lastClients = [];

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]);
    return parent;
  }
  function bytes(n) {
    var u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], i = 0;
    n = n || 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + ' ' + u[i];
  }
  function never(t) { return !t || t.indexOf('0001-') === 0; }
  function ago(t) {
    if (never(t)) return 'никогда';
    var s = Math.max(0, Math.round((Date.now() - new Date(t)) / 1000));
    if (s < 10) return 'сейчас';
    if (s < 60) return s + ' с назад';
    if (s < 3600) return Math.round(s / 60) + ' мин назад';
    if (s < 86400) return Math.round(s / 3600) + ' ч назад';
    return Math.round(s / 86400) + ' д назад';
  }
  function duration(s) {
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? d + ' д ' + h + ' ч' : h ? h + ' ч ' + m + ' мин' : m + ' мин';
  }
  function num(n) { return (n || 0).toLocaleString('ru-RU'); }
  function online(c) { return c.active > 0 || (Date.now() - new Date(c.last_seen)) < 120000; }
  function stranger(c) { return !c.own && (c.conns > 0 || c.queries > 0); }

  function api(method, path, body) {
    return fetch('/admin/api/' + path, {
      method: method,
      credentials: 'same-origin',
      headers: { 'X-ReDNS': '1', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      if (r.status === 401) { showLogin(); throw new Error('unauthorized'); }
      if (!r.ok) return r.text().then(function (t) { throw new Error(t.trim() || ('HTTP ' + r.status)); });
      return r.json();
    });
  }
  function fail(err) { if (err.message !== 'unauthorized') alert(err.message); }
  function quiet() {}

  function showLogin() {
    clearInterval(timer);
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    $('password').focus();
  }
  function showApp() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    route();
    refresh();
    clearInterval(timer);
    timer = setInterval(function () { if (!document.hidden) refresh(); }, 4000);
  }

  function route() {
    var v = location.hash.replace('#', '') || 'overview';
    if (!document.querySelector('section[data-view="' + v + '"]')) v = 'overview';
    view = v;
    document.querySelectorAll('section[data-view]').forEach(function (s) { s.classList.toggle('hidden', s.dataset.view !== v); });
    document.querySelectorAll('.nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.view === v); });
    if (v === 'devices') api('GET', 'devices').then(renderDevices).catch(quiet);
    if (v === 'log') loadLog();
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);

  function spark(values) {
    var ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'spark');
    svg.setAttribute('viewBox', '0 0 100 40');
    svg.setAttribute('preserveAspectRatio', 'none');
    var pts = values.length > 1 ? values : values.length ? [values[0], values[0]] : [0, 0];
    var max = (Math.max.apply(null, pts) || 1) * 1.2, step = 100 / (pts.length - 1), d = '';
    pts.forEach(function (v, i) { d += (i ? 'L' : 'M') + (i * step).toFixed(2) + ' ' + (38 - v / max * 32).toFixed(2); });
    var area = document.createElementNS(ns, 'path'), line = document.createElementNS(ns, 'path');
    area.setAttribute('class', 'a');
    area.setAttribute('d', d + 'L100 40L0 40Z');
    line.setAttribute('class', 'l');
    line.setAttribute('d', d);
    svg.appendChild(area);
    svg.appendChild(line);
    return svg;
  }
  function kpi(label, value, unit, rate, series) {
    var k = add(el('div', 'k'), el('span', null, label), rate ? el('span', 'rate', rate) : null);
    var v = el('div', 'v', value);
    if (unit) v.appendChild(el('small', null, unit));
    return add(el('div', 'card kpi'), k, v, spark(series));
  }
  function mini(label, value) { return add(el('div', 'card mini'), el('span', null, label), el('b', null, value)); }
  function push(arr, v) { arr.push(v); if (arr.length > 60) arr.shift(); }

  function renderOverview(o) {
    var s = o.stats || {}, info = o.info || {}, now = Date.now();
    var total = (s.proxy_bytes_down || 0) + (s.proxy_bytes_up || 0);
    var on = lastClients.filter(online);
    var str = on.filter(stranger);
    var qps = 0, mbps = 0;
    if (prev) {
      var dt = Math.max(1, (now - prev.t) / 1000);
      qps = Math.max(0, (s.queries - prev.q) / dt);
      mbps = Math.max(0, (total - prev.b) * 8 / dt / 1e6);
      push(hist.q, qps);
      push(hist.b, mbps);
    }
    push(hist.c, s.proxy_conns_active || 0);
    push(hist.o, on.length);
    prev = { t: now, q: s.queries || 0, b: total };

    $('ov-sub').textContent = (o.private ? 'Приватный режим' : 'Публичный режим') + ' · работает ' + duration(o.uptime_sec || 0);
    var k = $('kpis');
    k.textContent = '';
    add(k,
      kpi('Запросы', num(s.queries), null, qps.toFixed(1) + '/с', hist.q),
      kpi('Трафик', bytes(total), null, mbps.toFixed(1) + ' Мбит/с', hist.b),
      kpi('Соединения', num(s.proxy_conns_active), 'сейчас', num(s.proxy_conns_total) + ' всего', hist.c),
      kpi('Онлайн', String(on.length), 'клиентов', str.length ? str.length + ' чужих' : null, hist.o));
    var forwarded = s.forwarded || 0;
    var m = $('minis');
    m.textContent = '';
    add(m,
      mini('Заблокировано', num(s.blocked)),
      mini('Ответов из кэша', forwarded ? Math.round((s.cache_hits || 0) / forwarded * 100) + '%' : '—'),
      mini('Правил прокси', num(info.proxy_rules)),
      mini('Ошибок апстрима', num(s.upstream_errors)));

    var top = $('ov-top');
    top.textContent = '';
    var list = (s.top_proxied || []).slice(0, 8), max = list.length ? list[0].count : 1;
    if (!list.length) top.appendChild(el('div', 'empty', 'Пока пусто'));
    list.forEach(function (t) {
      var fill = el('i');
      fill.style.width = Math.max(4, t.count / max * 100) + '%';
      top.appendChild(add(el('div', 'bar'), fill, el('span', null, t.name), el('b', null, num(t.count))));
    });

    var strict = !!o.strict;
    $('strict').setAttribute('aria-checked', String(strict));
    $('strict-note').textContent = strict
      ? 'Включено. Прокси работает только для IP, с которых недавно был DNS-запрос с ключом. Чужие отрезаны, но при смене сети телефон может минуту ловить ошибки.'
      : 'Выключено. Прокси пропускает домены из списков с любого IP. Так надёжнее для телефонов, но тот, кто узнал IP сервера, может им пользоваться.';
    var kv = $('server-info');
    kv.textContent = '';
    [['Адрес', o.host], ['Версия', o.version], ['Режим', o.private ? 'приватный' : 'публичный'], ['Ты сейчас', o.you],
      ['Правил прокси', num(info.proxy_rules)], ['Правил блокировки', num(info.block_rules)], ['Записей в кэше', num(info.cache_entries)]]
      .forEach(function (r) { add(kv, el('dt', null, r[0]), el('dd', 'mono', r[1])); });
    renderBans(o.bans || []);
  }

  function title(c) {
    return add(el('div', 'title'), el('span', 'mono', c.prefix),
      c.own ? el('span', 'badge own', c.device) : el('span', 'badge stranger', 'чужой'),
      c.you ? el('span', 'badge', 'это ты') : null,
      c.banned ? el('span', 'badge bad', 'бан') : null);
  }
  function traffic(c) { return (c.down || c.up) ? el('span', null, '↓ ' + bytes(c.down) + '  ↑ ' + bytes(c.up)) : null; }

  function renderOnline(list) {
    var box = $('ov-online');
    box.textContent = '';
    var on = list.filter(online).slice(0, 7);
    if (!on.length) { box.appendChild(el('div', 'empty', 'Никого')); return; }
    on.forEach(function (c) {
      var meta = add(el('div', 'meta'), el('span', null, c.active ? c.active + ' соед.' : ago(c.last_seen)), traffic(c));
      box.appendChild(add(el('div', 'row'), el('span', 'status on'), add(el('div', 'grow'), title(c), meta)));
    });
  }

  function renderClients(list) {
    lastClients = list;
    var strangers = list.filter(function (c) { return stranger(c) && online(c); }).length;
    var nav = $('nav-strangers');
    nav.textContent = strangers;
    nav.classList.toggle('hidden', !strangers);
    $('ov-alert').classList.toggle('hidden', !strangers);
    $('ov-alert-text').textContent = strangers === 1 ? 'Через прокси ходит чужой IP' : 'Через прокси ходят чужие IP: ' + strangers;
    renderOnline(list);

    var box = $('clients');
    box.textContent = '';
    var shown = list.filter(function (c) {
      if (filter === 'strangers') return stranger(c);
      if (filter === 'online') return online(c);
      return true;
    });
    if (!shown.length) { box.appendChild(el('div', 'empty', filter === 'strangers' ? 'Чужих нет' : 'Пусто')); return; }
    shown.forEach(function (c) {
      var meta = add(el('div', 'meta'),
        el('span', null, ago(c.last_seen)),
        c.queries ? el('span', null, 'DNS ' + num(c.queries) + (c.proto ? ' · ' + c.proto : '')) : null,
        c.conns ? el('span', null, 'прокси ' + num(c.conns) + (c.active ? ' · сейчас ' + c.active : '')) : null,
        traffic(c));
      var body = add(el('div', 'grow'), title(c), meta);
      if (c.hosts && c.hosts.length) body.appendChild(el('div', 'hosts', c.hosts.join('  ')));
      var ops = el('div', 'ops');
      if (!c.you) {
        var kick = el('button', 'btn sm ghost', 'Отключить');
        kick.addEventListener('click', function () { api('POST', 'kick', { prefix: c.prefix }).then(refresh).catch(fail); });
        var ban = el('button', 'btn sm danger', c.banned ? 'Разбанить' : 'Бан');
        ban.addEventListener('click', function () {
          if (c.banned) { api('POST', 'bans/remove', { prefix: c.prefix }).then(refresh).catch(fail); return; }
          if (!confirm('Забанить ' + c.prefix + '? DNS и прокси для него отключатся сразу.')) return;
          api('POST', 'bans/add', { target: c.prefix, reason: c.own ? c.device : 'чужой' }).then(refresh).catch(fail);
        });
        add(ops, kick, ban);
      }
      box.appendChild(add(el('div', 'row'), el('span', 'status' + (online(c) ? ' on' : '')), body, ops));
    });
  }

  function renderDevices(list) {
    var box = $('devices');
    box.textContent = '';
    if (!list.length) { box.appendChild(el('div', 'empty', 'Нет устройств')); return; }
    list.forEach(function (d) {
      var t = add(el('div', 'title'), el('span', null, d.name), d.source === 'config' ? el('span', 'badge', 'из конфига') : null);
      var meta = add(el('div', 'meta'),
        el('span', null, never(d.last_seen) ? 'ещё не подключался' : 'был ' + ago(d.last_seen)),
        el('span', null, num(d.queries) + ' запросов'),
        d.ips.length ? el('span', 'mono', d.ips.join(', ')) : null);
      var copy = el('button', 'btn sm ghost', 'Ссылка');
      copy.addEventListener('click', function () {
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(d.setup_url).then(function () {
          copy.textContent = 'Скопировано';
          setTimeout(function () { copy.textContent = 'Ссылка'; }, 1400);
        });
      });
      var revoke = el('button', 'btn sm danger', 'Отозвать');
      revoke.addEventListener('click', function () {
        if (!confirm('Отозвать ключ «' + d.name + '»? Устройство перестанет работать.')) return;
        api('POST', 'devices/revoke', { token: d.token }).then(function () { return api('GET', 'devices'); }).then(renderDevices).catch(fail);
      });
      var avatar = el('span', 'avatar', d.name.trim().charAt(0) || '?');
      box.appendChild(add(el('div', 'row'), avatar, add(el('div', 'grow'), t, meta), add(el('div', 'ops'), copy, revoke)));
    });
  }

  function renderBans(list) {
    var box = $('bans');
    box.textContent = '';
    if (!list.length) { box.appendChild(el('div', 'empty', 'Банов нет')); return; }
    list.forEach(function (b) {
      var un = el('button', 'btn sm ghost', 'Снять');
      un.addEventListener('click', function () { api('POST', 'bans/remove', { prefix: b.prefix }).then(refresh).catch(fail); });
      var body = add(el('div', 'grow'), add(el('div', 'title'), el('span', 'mono', b.prefix)),
        add(el('div', 'meta'), el('span', null, ago(b.created)), b.reason ? el('span', null, b.reason) : null));
      box.appendChild(add(el('div', 'row'), el('span', 'status'), body, add(el('div', 'ops'), un)));
    });
  }

  function renderLog(list) {
    var box = $('log');
    box.textContent = '';
    if (!list.length) { box.appendChild(el('div', 'empty', 'Пусто')); return; }
    list.slice(0, 100).forEach(function (e) {
      var t = new Date(e.time);
      var hh = ('0' + t.getHours()).slice(-2) + ':' + ('0' + t.getMinutes()).slice(-2) + ':' + ('0' + t.getSeconds()).slice(-2);
      var cls = e.action === 'proxy' ? 'badge proxy' : e.action === 'block' ? 'badge block' : 'badge';
      box.appendChild(add(el('div', 'row'), el('span', 'muted', hh), el('span', 'cl muted', e.client), el('span', null, e.name), add(el('span'), el('span', cls, e.action))));
    });
  }
  function loadLog() { api('GET', 'log?n=200&q=' + encodeURIComponent(logQuery)).then(renderLog).catch(quiet); }

  function refresh() {
    api('GET', 'clients').then(function (list) {
      renderClients(list);
      return api('GET', 'overview');
    }).then(renderOverview).catch(quiet);
    if (view === 'devices') api('GET', 'devices').then(renderDevices).catch(quiet);
    if (view === 'log') loadLog();
  }

  $('login-form').addEventListener('submit', function (e) {
    e.preventDefault();
    $('login-error').textContent = '';
    api('POST', 'login', { password: $('password').value }).then(function () {
      $('password').value = '';
      showApp();
    }).catch(function (err) {
      $('login-error').textContent = err.message === 'wrong password' ? 'Неверный пароль'
        : err.message === 'too many attempts' ? 'Слишком много попыток, подожди 15 минут' : err.message;
    });
  });
  $('logout').addEventListener('click', function () { api('POST', 'logout').finally(showLogin); });

  $('dev-new').addEventListener('click', function () {
    $('dev-form-card').classList.toggle('hidden');
    $('dev-name').focus();
  });
  $('dev-form').addEventListener('submit', function (e) {
    e.preventDefault();
    $('dev-error').textContent = '';
    api('POST', 'devices/add', { name: $('dev-name').value }).then(function (d) {
      $('dev-name').value = '';
      $('dev-url').textContent = d.setup_url;
      $('dev-copy').textContent = 'Копировать';
      $('dev-created').classList.remove('hidden');
      return api('GET', 'devices');
    }).then(renderDevices).catch(function (err) { $('dev-error').textContent = err.message; });
  });
  $('dev-copy').addEventListener('click', function () {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText($('dev-url').textContent).then(function () { $('dev-copy').textContent = 'Скопировано'; });
  });

  $('ban-form').addEventListener('submit', function (e) {
    e.preventDefault();
    $('ban-error').textContent = '';
    api('POST', 'bans/add', { target: $('ban-target').value, reason: $('ban-reason').value }).then(function () {
      $('ban-target').value = '';
      $('ban-reason').value = '';
      refresh();
    }).catch(function (err) { $('ban-error').textContent = err.message; });
  });

  function setFilter(f) {
    filter = f;
    document.querySelectorAll('#filter button').forEach(function (x) { x.setAttribute('aria-pressed', String(x.dataset.f === f)); });
    renderClients(lastClients);
  }
  document.querySelectorAll('#filter button').forEach(function (b) { b.addEventListener('click', function () { setFilter(b.dataset.f); }); });
  $('ov-alert-go').addEventListener('click', function () { setFilter('strangers'); });

  $('strict').addEventListener('click', function () {
    var next = $('strict').getAttribute('aria-checked') !== 'true';
    api('POST', 'settings', { strict_proxy: next }).then(refresh).catch(fail);
  });

  var debounce = null;
  $('log-filter').addEventListener('input', function () {
    clearTimeout(debounce);
    debounce = setTimeout(function () { logQuery = $('log-filter').value.trim(); loadLog(); }, 250);
  });

  api('GET', 'overview').then(showApp).catch(quiet);
})();
