(function () {
  var $ = function (id) {
    return document.getElementById(id);
  };
  var view = "overview",
    filter = "all",
    logQuery = "",
    logTab = "conns",
    timer = null;
  var hist = { q: [], b: [], c: [], o: [] },
    prev = null,
    lastClients = [];

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++)
      if (arguments[i]) parent.appendChild(arguments[i]);
    return parent;
  }
  function bytes(n) {
    var u = ["Б", "КБ", "МБ", "ГБ", "ТБ"],
      i = 0;
    n = n || 0;
    while (n >= 1024 && i < u.length - 1) {
      n /= 1024;
      i++;
    }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i];
  }
  function never(t) {
    return !t || t.indexOf("0001-") === 0;
  }
  function ago(t) {
    if (never(t)) return "никогда";
    var s = Math.max(0, Math.round((Date.now() - new Date(t)) / 1000));
    if (s < 10) return "сейчас";
    if (s < 60) return s + " с назад";
    if (s < 3600) return Math.round(s / 60) + " мин назад";
    if (s < 86400) return Math.round(s / 3600) + " ч назад";
    return Math.round(s / 86400) + " д назад";
  }
  function duration(s) {
    var d = Math.floor(s / 86400),
      h = Math.floor((s % 86400) / 3600),
      m = Math.floor((s % 3600) / 60);
    return d ? d + " д " + h + " ч" : h ? h + " ч " + m + " мин" : m + " мин";
  }
  function pad(n) {
    return ("0" + n).slice(-2);
  }
  function clock(t) {
    t = new Date(t);
    return (
      pad(t.getHours()) + ":" + pad(t.getMinutes()) + ":" + pad(t.getSeconds())
    );
  }
  function stamp(t) {
    t = new Date(t);
    var hm = pad(t.getHours()) + ":" + pad(t.getMinutes());
    if (t.toDateString() === new Date().toDateString()) return "сегодня " + hm;
    return (
      t
        .toLocaleDateString("ru-RU", { day: "numeric", month: "short" })
        .replace(".", "") +
      " " +
      hm
    );
  }
  function ms(n) {
    if (n < 1000) return n + " мс";
    if (n < 60000) return (n / 1000).toFixed(n < 10000 ? 1 : 0) + " с";
    return duration(Math.round(n / 1000));
  }
  function plural(n, one, few, many) {
    var m10 = n % 10,
      m100 = n % 100;
    var w =
      m10 === 1 && m100 !== 11
        ? one
        : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)
          ? few
          : many;
    return n + " " + w;
  }
  function num(n) {
    return (n || 0).toLocaleString("ru-RU");
  }
  function online(c) {
    return c.active > 0 || Date.now() - new Date(c.last_seen) < 120000;
  }
  function stranger(c) {
    return !c.own && (c.conns > 0 || c.queries > 0);
  }

  function api(method, path, body) {
    return fetch("/admin/api/" + path, {
      method: method,
      credentials: "same-origin",
      headers: { "X-ReDNS": "1", "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (r) {
      if (r.status === 401) {
        showLogin();
        throw new Error("unauthorized");
      }
      if (!r.ok)
        return r.text().then(function (t) {
          throw new Error(t.trim() || "HTTP " + r.status);
        });
      return r.json();
    });
  }
  function fail(err) {
    if (err.message !== "unauthorized") alert(err.message);
  }
  function quiet() {}

  function showLogin() {
    clearInterval(timer);
    $("app").classList.add("hidden");
    $("login").classList.remove("hidden");
    $("password").focus();
  }
  function showApp() {
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    route();
    refresh();
    clearInterval(timer);
    timer = setInterval(function () {
      if (!document.hidden) refresh();
    }, 4000);
  }

  function route() {
    var v = location.hash.replace("#", "") || "overview";
    if (!document.querySelector('section[data-view="' + v + '"]'))
      v = "overview";
    view = v;
    document.querySelectorAll("section[data-view]").forEach(function (s) {
      s.classList.toggle("hidden", s.dataset.view !== v);
    });
    document.querySelectorAll(".nav a").forEach(function (a) {
      a.classList.toggle("active", a.dataset.view === v);
    });
    if (v === "devices") refreshPeople();
    if (v === "log") loadLog();
    if (v === "settings") loadSessions();
    window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", route);

  function spark(values) {
    var ns = "http://www.w3.org/2000/svg",
      svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "spark");
    svg.setAttribute("viewBox", "0 0 100 40");
    svg.setAttribute("preserveAspectRatio", "none");
    var pts =
      values.length > 1
        ? values
        : values.length
          ? [values[0], values[0]]
          : [0, 0];
    var max = (Math.max.apply(null, pts) || 1) * 1.2,
      step = 100 / (pts.length - 1),
      d = "";
    pts.forEach(function (v, i) {
      d +=
        (i ? "L" : "M") +
        (i * step).toFixed(2) +
        " " +
        (38 - (v / max) * 32).toFixed(2);
    });
    var area = document.createElementNS(ns, "path"),
      line = document.createElementNS(ns, "path");
    area.setAttribute("class", "a");
    area.setAttribute("d", d + "L100 40L0 40Z");
    line.setAttribute("class", "l");
    line.setAttribute("d", d);
    svg.appendChild(area);
    svg.appendChild(line);
    return svg;
  }
  function kpi(label, value, unit, rate, series, warn) {
    var k = add(
      el("div", "k"),
      el("span", null, label),
      rate ? el("span", warn ? "rate warn" : "rate", rate) : null,
    );
    var v = el("div", "v", value);
    if (unit) v.appendChild(el("small", null, unit));
    return add(el("div", "card kpi"), k, v, spark(series));
  }
  function mini(label, value) {
    return add(
      el("div", "mini"),
      el("span", null, label),
      el("b", null, value),
    );
  }
  function push(arr, v) {
    arr.push(v);
    if (arr.length > 60) arr.shift();
  }

  function renderOverview(o) {
    var s = o.stats || {},
      info = o.info || {},
      now = Date.now();
    var total = (s.proxy_bytes_down || 0) + (s.proxy_bytes_up || 0);
    var on = lastClients.filter(online);
    var str = on.filter(stranger);
    var qps = 0,
      mbps = 0;
    if (prev) {
      var dt = Math.max(1, (now - prev.t) / 1000);
      qps = Math.max(0, (s.queries - prev.q) / dt);
      mbps = Math.max(0, ((total - prev.b) * 8) / dt / 1e6);
      push(hist.q, qps);
      push(hist.b, mbps);
    }
    push(hist.c, s.proxy_conns_active || 0);
    push(hist.o, on.length);
    prev = { t: now, q: s.queries || 0, b: total };

    var sub = $("ov-sub");
    sub.textContent = "";
    add(
      sub,
      el("span", "badge ok", o.private ? "Приватный режим" : "Публичный режим"),
      el("span", "badge", "Работает " + duration(o.uptime_sec || 0)),
    );
    var k = $("kpis");
    k.textContent = "";
    add(
      k,
      kpi("Запросы", num(s.queries), null, qps.toFixed(1) + "/с", hist.q),
      kpi("Трафик", bytes(total), null, mbps.toFixed(1) + " Мбит/с", hist.b),
      kpi(
        "Соединения",
        num(s.proxy_conns_active),
        "сейчас",
        num(s.proxy_conns_total) + " всего",
        hist.c,
      ),
      kpi(
        "Онлайн",
        String(on.length),
        "клиентов",
        str.length ? str.length + " чужих" : null,
        hist.o,
        true,
      ),
    );
    var forwarded = s.forwarded || 0;
    var m = $("minis");
    m.textContent = "";
    add(
      m,
      mini("Заблокировано", num(s.blocked)),
      mini(
        "Ответов из кэша",
        forwarded
          ? Math.round(((s.cache_hits || 0) / forwarded) * 100) + "%"
          : "—",
      ),
      mini("Правил прокси", num(info.proxy_rules)),
      mini("Ошибок апстрима", num(s.upstream_errors)),
    );

    var top = $("ov-top");
    top.textContent = "";
    var list = (s.top_proxied || []).slice(0, 8),
      max = list.length ? list[0].count : 1;
    if (!list.length) top.appendChild(el("div", "empty", "Пока пусто"));
    list.forEach(function (t) {
      var fill = el("i");
      fill.style.width = Math.max(4, (t.count / max) * 100) + "%";
      top.appendChild(
        add(
          el("div", "bar"),
          fill,
          el("span", null, t.name),
          el("b", null, num(t.count)),
        ),
      );
    });

    var strict = !!o.strict;
    $("strict").setAttribute("aria-checked", String(strict));
    $("strict-note").textContent = strict
      ? "Включено. Прокси работает только для IP, с которых недавно был DNS-запрос с ключом. Чужие отрезаны, но при смене сети телефон может минуту ловить ошибки."
      : "Выключено. Прокси пропускает домены из списков с любого IP. Так надёжнее для телефонов, но тот, кто узнал IP сервера, может им пользоваться.";
    var kv = $("server-info");
    kv.textContent = "";
    [
      ["Адрес", o.host],
      ["Версия", o.version],
      ["Режим", o.private ? "приватный" : "публичный"],
      ["Ты сейчас", o.you],
      ["Правил прокси", num(info.proxy_rules)],
      ["Правил блокировки", num(info.block_rules)],
      ["Записей в кэше", num(info.cache_entries)],
    ].forEach(function (r) {
      add(kv, el("dt", null, r[0]), el("dd", "mono", r[1]));
    });
    renderBans(o.bans || []);
  }

  function title(c) {
    return add(
      el("div", "title"),
      el("span", "mono", c.prefix),
      c.own
        ? el("span", "badge own", c.device)
        : el("span", "badge stranger", "чужой"),
      c.you ? el("span", "badge", "это ты") : null,
      c.banned ? el("span", "badge bad", "бан") : null,
    );
  }
  function traffic(c) {
    return c.down || c.up
      ? el("span", null, "↓ " + bytes(c.down) + "  ↑ " + bytes(c.up))
      : null;
  }

  function renderOnline(list) {
    var box = $("ov-online");
    box.textContent = "";
    var on = list.filter(online).slice(0, 7);
    if (!on.length) {
      box.appendChild(el("div", "empty", "Никого"));
      return;
    }
    on.forEach(function (c) {
      var meta = add(
        el("div", "meta"),
        el("span", null, c.active ? c.active + " соед." : ago(c.last_seen)),
        traffic(c),
      );
      box.appendChild(
        add(
          el("div", "row"),
          el("span", "status on"),
          add(el("div", "grow"), title(c), meta),
        ),
      );
    });
  }

  function renderClients(list) {
    lastClients = list;
    var strangers = list.filter(function (c) {
      return stranger(c) && online(c);
    }).length;
    var nav = $("nav-strangers");
    nav.textContent = strangers;
    nav.classList.toggle("hidden", !strangers);
    $("ov-alert").classList.toggle("hidden", !strangers);
    $("ov-alert-text").textContent =
      strangers === 1
        ? "Через прокси ходит чужой IP"
        : "Через прокси ходят чужие IP: " + strangers;
    renderOnline(list);

    var counts = {
      all: list.length,
      strangers: list.filter(stranger).length,
      online: list.filter(online).length,
    };
    Object.keys(counts).forEach(function (f) {
      $("f-" + f).textContent = counts[f] || "";
    });

    var box = $("clients");
    box.textContent = "";
    var shown = list.filter(function (c) {
      if (filter === "strangers") return stranger(c);
      if (filter === "online") return online(c);
      return true;
    });
    if (!shown.length) {
      box.appendChild(
        el("div", "empty", filter === "strangers" ? "Чужих нет" : "Пусто"),
      );
      return;
    }
    box.appendChild(
      add(
        el("div", "row th"),
        el("span", null, "IP и устройство"),
        el("span", null, "Активность"),
        el("span", null, "DNS"),
        el("span", null, "Прокси"),
        el("span", "r", "Трафик ↓ / ↑"),
        el("span", "r", "Действия"),
      ),
    );
    function cell(label, text, cls) {
      if (!text) return el("span", "c none", "—");
      var c = el("span", "c" + (cls ? " " + cls : ""), text);
      c.dataset.label = label;
      return c;
    }
    shown.forEach(function (c) {
      var on = online(c);
      var body = add(el("div", "grow"), title(c));
      if (c.hosts && c.hosts.length)
        body.appendChild(el("div", "hosts", c.hosts.join("  ")));
      var main = add(
        el("div", "main"),
        el("span", "status" + (on ? " on" : "")),
        body,
      );
      var seen = cell(
        "Активность",
        c.active ? "сейчас" : ago(c.last_seen),
        on ? "seen-on" : "",
      );
      var dns = cell(
        "DNS",
        c.queries ? num(c.queries) + (c.proto ? " · " + c.proto : "") : "",
      );
      var px = cell(
        "Прокси",
        c.conns
          ? num(c.conns) + (c.active ? " · " + c.active + " сейчас" : "")
          : "",
      );
      var tr = cell(
        "Трафик",
        c.down || c.up ? "↓ " + bytes(c.down) + " / ↑ " + bytes(c.up) : "",
        "r",
      );
      var ops = el("div", "ops");
      if (!c.you) {
        var kick = el("button", "btn sm ghost", "Отключить");
        kick.addEventListener("click", function () {
          api("POST", "kick", { prefix: c.prefix }).then(refresh).catch(fail);
        });
        var ban = el("button", "btn sm danger", c.banned ? "Разбанить" : "Бан");
        ban.addEventListener("click", function () {
          if (c.banned) {
            api("POST", "bans/remove", { prefix: c.prefix })
              .then(refresh)
              .catch(fail);
            return;
          }
          if (
            !confirm(
              "Забанить " +
                c.prefix +
                "? DNS и прокси для него отключатся сразу.",
            )
          )
            return;
          api("POST", "bans/add", {
            target: c.prefix,
            reason: c.own ? c.device : "чужой",
          })
            .then(refresh)
            .catch(fail);
        });
        add(ops, kick, ban);
      }
      box.appendChild(add(el("div", "row"), main, seen, dns, px, tr, ops));
    });
  }

  var kindNames = {
    iphone: "iPhone",
    ipad: "iPad",
    mac: "Mac",
    android: "Android",
    windows: "Windows",
    other: "Устройство",
  };
  var lastDevices = [];

  function icon(id) {
    var ns = "http://www.w3.org/2000/svg",
      svg = document.createElementNS(ns, "svg"),
      use = document.createElementNS(ns, "use");
    use.setAttribute("href", "#" + id);
    svg.appendChild(use);
    return svg;
  }
  function kindIcon(kind) {
    return add(
      el("span", "kind-ico"),
      icon(kind === "mac" || kind === "windows" ? "i-laptop" : "i-devices"),
    );
  }

  function howto(kind) {
    var p = el("p", "howto");
    var t = {
      iphone: [
        "Открой ссылку на iPhone в ",
        "Safari",
        ", нажми «Скачать профиль», потом Настройки → «Профиль загружен» → Установить.",
      ],
      ipad: [
        "Открой ссылку на iPad в ",
        "Safari",
        ", нажми «Скачать профиль», потом Настройки → «Профиль загружен» → Установить.",
      ],
      mac: [
        "Открой ссылку на Mac в ",
        "Safari",
        ", нажми «Скачать профиль», потом Системные настройки → Основные → Устройства и управление → Установить.",
      ],
      android: [
        "Поставь из Google Play ",
        "Intra или RethinkDNS",
        ", открой ссылку на телефоне и вставь в приложение адрес с этой страницы.",
      ],
      windows: [
        "Открой ссылку на компьютере, там ",
        "пошаговая инструкция",
        " для Windows и браузеров.",
      ],
      other: [
        "Открой ссылку на устройстве, там ",
        "инструкция",
        " под разные системы.",
      ],
    }[kind] || ["Открой ссылку на устройстве, там ", "инструкция", "."];
    return add(
      p,
      document.createTextNode(t[0]),
      el("b", null, t[1]),
      document.createTextNode(t[2]),
    );
  }

  function linkBlock(d) {
    var box = el("div", "link-box");
    var copy = el("button", "btn sm ghost", "Копировать");
    copy.type = "button";
    copy.addEventListener("click", function () {
      if (navigator.clipboard)
        navigator.clipboard.writeText(d.setup_url).then(function () {
          copy.textContent = "Скопировано";
        });
    });
    add(box, el("code", null, d.setup_url), copy);
    var wrap = add(el("div"), box);
    if (navigator.share) {
      var share = el("button", "btn", "Отправить");
      share.type = "button";
      share.style.width = "100%";
      share.style.marginTop = "10px";
      share.addEventListener("click", function () {
        navigator
          .share({
            title: "ReDNS для " + d.owner,
            text: "Подключение к ReDNS (" + (kindNames[d.kind] || d.name) + ")",
            url: d.setup_url,
          })
          .catch(quiet);
      });
      wrap.appendChild(share);
    }
    return wrap;
  }

  function deviceCard(box, d, title) {
    box.textContent = "";
    var img = el("img", "qr");
    img.alt = "QR-код";
    img.src =
      "/admin/api/qr?token=" + encodeURIComponent(d.token) + "&t=" + Date.now();
    var close = el("button", "btn", "Готово");
    close.type = "button";
    close.addEventListener("click", function () {
      box.closest("dialog").close();
    });
    add(
      box,
      el("h2", null, title),
      el("p", "muted", d.owner + " · " + d.name),
      img,
      linkBlock(d),
      howto(d.kind),
      add(el("div", "dialog-actions"), close),
    );
  }

  function showQR(d) {
    deviceCard($("qr-body"), d, "Подключение");
    $("qr-dialog").showModal();
  }

  function renderPeople(list) {
    lastDevices = list;
    var box = $("people");
    box.textContent = "";
    var owners = [],
      groups = {};
    list.forEach(function (d) {
      if (!groups[d.owner]) {
        groups[d.owner] = [];
        owners.push(d.owner);
      }
      groups[d.owner].push(d);
    });
    var dl = $("owners");
    dl.textContent = "";
    owners.forEach(function (o) {
      if (o !== "Я") {
        var op = el("option");
        op.value = o;
        dl.appendChild(op);
      }
    });
    if (!owners.length) {
      box.appendChild(
        add(
          el("div", "card"),
          el("div", "empty", "Пока никого. Нажми «Добавить устройство»."),
        ),
      );
      return;
    }
    owners.forEach(function (owner) {
      var devs = groups[owner],
        on = devs.some(function (d) {
          return d.online;
        });
      var down = 0,
        up = 0,
        last = "";
      devs.forEach(function (d) {
        down += d.down;
        up += d.up;
        if (!never(d.last_used) && d.last_used > last) last = d.last_used;
      });
      var status = on
        ? el("span", "on-text", "онлайн")
        : el("span", null, last ? "был " + ago(last) : "ещё не подключался");
      var more = el("button", "btn sm ghost", "+ устройство");
      more.addEventListener("click", function () {
        openAdd(owner);
      });
      var off = el("button", "btn sm danger", "Отключить всех");
      off.addEventListener("click", function () {
        if (
          !confirm(
            "Отключить все устройства «" +
              owner +
              "»? Их ссылки перестанут работать.",
          )
        )
          return;
        api("POST", "devices/revoke-owner", { owner: owner })
          .then(refreshPeople)
          .catch(fail);
      });
      var head = add(
        el("div", "person-head"),
        el("span", "avatar", owner.charAt(0)),
        add(
          el("div", "grow"),
          el("div", "name", owner),
          add(
            el("div", "meta"),
            status,
            el("span", null, devs.length + " устр."),
            down || up
              ? el("span", null, "↓ " + bytes(down) + "  ↑ " + bytes(up))
              : null,
          ),
        ),
        add(el("div", "ops"), more, owner === "Я" ? null : off),
      );
      var table = el("div", "table");
      devs.forEach(function (d) {
        var shared = d.clients > 1 || d.networks > 4;
        var t = add(
          el("div", "title"),
          el("span", null, d.name),
          d.online ? el("span", "badge own", "онлайн") : null,
          shared
            ? el(
                "span",
                "badge stranger",
                "похоже, ключ не на одном устройстве",
              )
            : null,
        );
        var meta = add(
          el("div", "meta"),
          el(
            "span",
            null,
            never(d.last_used) ? "ещё не подключалось" : ago(d.last_used),
          ),
          d.queries ? el("span", null, num(d.queries) + " DNS") : null,
          d.conns ? el("span", null, num(d.conns) + " соед.") : null,
          d.down || d.up
            ? el("span", null, "↓ " + bytes(d.down) + "  ↑ " + bytes(d.up))
            : null,
          d.networks > 1
            ? el(
                "span",
                null,
                plural(d.networks, "сеть", "сети", "сетей") + " за сутки",
              )
            : null,
          d.clients > 1
            ? el(
                "span",
                null,
                plural(d.clients, "клиент", "клиента", "клиентов"),
              )
            : null,
        );
        var body = add(el("div", "grow"), t, meta);
        if (shared) {
          var reset = el("button", "btn sm ghost", "Это мои, сбросить");
          reset.addEventListener("click", function () {
            api("POST", "devices/reset", { token: d.token })
              .then(refreshPeople)
              .catch(fail);
          });
          body.appendChild(
            add(
              el("div", "meta"),
              el(
                "span",
                null,
                d.clients > 1
                  ? "Ключом пользуются разные системы или программы. Если это не обновление и не твой второй браузер, ключ поставили куда-то ещё."
                  : "Ключ приходил из многих сетей за сутки. Возможно, им поделились.",
              ),
              reset,
            ),
          );
        }
        if (d.hosts.length)
          body.appendChild(el("div", "hosts", d.hosts.join("  ")));
        var qrb = el("button", "btn sm ghost", "QR и ссылка");
        qrb.addEventListener("click", function () {
          showQR(d);
        });
        var logb = el("button", "btn sm ghost", "Журнал");
        logb.disabled = !d.ips.length;
        logb.addEventListener("click", function () {
          logQuery = d.ips[0].split("/")[0];
          $("log-filter").value = logQuery;
          location.hash = "#log";
        });
        var rm = el("button", "btn sm danger", "Отключить");
        rm.addEventListener("click", function () {
          if (
            !confirm(
              "Отключить «" +
                owner +
                " · " +
                d.name +
                "»? Ссылка этого устройства перестанет работать.",
            )
          )
            return;
          api("POST", "devices/revoke", { token: d.token })
            .then(refreshPeople)
            .catch(fail);
        });
        table.appendChild(
          add(
            el("div", "row"),
            kindIcon(d.kind),
            body,
            add(el("div", "ops"), qrb, logb, rm),
          ),
        );
      });
      box.appendChild(add(el("div", "card"), head, table));
    });
  }
  function refreshPeople() {
    return api("GET", "devices").then(renderPeople).catch(quiet);
  }

  var addWho = "me",
    addKind = "iphone";
  function press(groupId, attr, value) {
    document.querySelectorAll("#" + groupId + " button").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.dataset[attr] === value));
    });
  }
  function openAdd(owner) {
    addWho = owner && owner !== "Я" ? "other" : "me";
    addKind = "iphone";
    press("add-who", "who", addWho);
    press("add-kind", "kind", addKind);
    $("add-owner").value = addWho === "other" ? owner : "";
    $("add-owner").classList.toggle("hidden", addWho !== "other");
    $("add-error").textContent = "";
    $("add-step1").classList.remove("hidden");
    $("add-step2").classList.add("hidden");
    $("add-dialog").showModal();
  }
  document.querySelectorAll("#add-who button").forEach(function (b) {
    b.addEventListener("click", function () {
      addWho = b.dataset.who;
      press("add-who", "who", addWho);
      $("add-owner").classList.toggle("hidden", addWho !== "other");
      if (addWho === "other") $("add-owner").focus();
    });
  });
  document.querySelectorAll("#add-kind button").forEach(function (b) {
    b.addEventListener("click", function () {
      addKind = b.dataset.kind;
      press("add-kind", "kind", addKind);
    });
  });
  $("add-create").addEventListener("click", function () {
    var owner = addWho === "me" ? "Я" : $("add-owner").value.trim();
    if (!owner) {
      $("add-error").textContent = "Напиши имя человека";
      return;
    }
    $("add-error").textContent = "";
    api("POST", "devices/add", { owner: owner, kind: addKind })
      .then(function (d) {
        $("add-step1").classList.add("hidden");
        var step2 = $("add-step2");
        step2.classList.remove("hidden");
        deviceCard(step2, d, "Готово");
        refreshPeople();
      })
      .catch(function (err) {
        $("add-error").textContent = err.message;
      });
  });

  function renderBans(list) {
    var box = $("bans");
    box.textContent = "";
    if (!list.length) {
      box.appendChild(el("div", "empty", "Банов нет"));
      return;
    }
    list.forEach(function (b) {
      var un = el("button", "btn sm ghost", "Снять");
      un.addEventListener("click", function () {
        api("POST", "bans/remove", { prefix: b.prefix })
          .then(refresh)
          .catch(fail);
      });
      var body = add(
        el("div", "grow"),
        add(el("div", "title"), el("span", "mono", b.prefix)),
        add(
          el("div", "meta"),
          el("span", null, ago(b.created)),
          b.reason ? el("span", null, b.reason) : null,
        ),
      );
      box.appendChild(
        add(
          el("div", "row"),
          el("span", "status"),
          body,
          add(el("div", "ops"), un),
        ),
      );
    });
  }

  var tabs = {
    conns: {
      path: "conns",
      sub: "Через прокси: кто, куда, сколько трафика. Видно после закрытия соединения.",
      hint: "Сайт, IP или имя устройства",
      note: "Последние соединения, только в памяти. После перезапуска сервера список начинается заново.",
    },
    dns: {
      path: "log",
      sub: "DNS-запросы: что спрашивали и что ответил сервер.",
      hint: "Домен, IP, proxy или block",
      note: "Последние запросы, только в памяти.",
    },
    audit: {
      path: "audit",
      sub: "Что делали в админке и что сервер заметил сам: входы, баны, подбор ключей.",
      hint: "Действие, IP или имя",
      note: "Хранится на сервере в audit.log, последние 2000 записей. Переживает перезапуск.",
    },
  };
  function who(e) {
    return e.device || e.client;
  }
  function renderDNS(box, list) {
    list.slice(0, 150).forEach(function (e) {
      var cls =
        e.action === "proxy"
          ? "badge proxy"
          : e.action === "block"
            ? "badge block"
            : "badge";
      box.appendChild(
        add(
          el("div", "row"),
          el("span", "muted", clock(e.time)),
          el("span", "cl muted", e.client),
          el("span", null, e.name),
          add(el("span"), el("span", cls, e.action)),
        ),
      );
    });
  }
  function renderConns(box, list) {
    list.slice(0, 150).forEach(function (c) {
      var host = c.host + (c.port && c.port !== 443 ? ":" + c.port : "");
      var row = add(
        el("div", "row conn" + (c.err ? " err" : "")),
        el("span", "muted", clock(c.time)),
        el("span", "cl muted", who(c)),
        el("span", "host", c.err ? host + " · " + c.err : host),
        el(
          "span",
          "right muted",
          "↓ " + bytes(c.down) + " ↑ " + bytes(c.up) + " · " + ms(c.ms),
        ),
      );
      row.title = c.client + (c.device ? " · " + c.device : "");
      box.appendChild(row);
    });
  }
  function renderAudit(box, list) {
    list.forEach(function (e) {
      var act = add(
        el("span", "act"),
        el("b", null, e.action),
        e.detail ? el("span", "sub", " · " + e.detail) : null,
      );
      box.appendChild(
        add(
          el("div", "row ev" + (e.level === "warn" ? " warn" : "")),
          el("span", "muted", stamp(e.time)),
          act,
          el("span", "cl muted mono", e.ip || ""),
        ),
      );
    });
  }
  function loadLog() {
    var tab = logTab,
      t = tabs[tab];
    $("log-sub").textContent = t.sub;
    $("log-filter").placeholder = t.hint;
    $("log-note").textContent = t.note;
    api(
      "GET",
      t.path +
        "?n=" +
        (tab === "audit" ? 300 : 200) +
        "&q=" +
        encodeURIComponent(logQuery),
    )
      .then(function (list) {
        if (tab !== logTab) return;
        var box = $("log");
        box.textContent = "";
        if (!list.length) {
          box.appendChild(
            el("div", "empty", logQuery ? "Ничего не нашлось" : "Пока пусто"),
          );
          return;
        }
        ({ conns: renderConns, dns: renderDNS, audit: renderAudit })[tab](
          box,
          list,
        );
      })
      .catch(quiet);
  }
  function setTab(tab) {
    logTab = tab;
    press("log-tabs", "tab", tab);
    loadLog();
  }
  document.querySelectorAll("#log-tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      setTab(b.dataset.tab);
    });
  });

  function renderRecent(list) {
    var box = $("ov-audit");
    box.textContent = "";
    if (!list.length) {
      box.appendChild(el("div", "empty", "Пока ничего не происходило"));
      return;
    }
    list.forEach(function (e) {
      box.appendChild(
        add(
          el("div", "ev-line" + (e.level === "warn" ? " warn" : "")),
          el("span", "when", stamp(e.time)),
          add(
            el("span", "what"),
            el("b", null, e.action),
            e.detail ? el("span", null, " · " + e.detail) : null,
          ),
          el("span", "ip", e.ip || ""),
        ),
      );
    });
  }

  function renderSessions(list) {
    var box = $("sessions");
    box.textContent = "";
    $("end-others").classList.toggle("hidden", list.length < 2);
    list.forEach(function (s) {
      var body = add(
        el("div", "grow"),
        add(
          el("div", "title"),
          el("span", null, s.agent || "Браузер"),
          s.current ? el("span", "badge own", "это ты") : null,
        ),
        add(
          el("div", "meta"),
          el("span", "mono", s.ip),
          el("span", null, "вошёл " + ago(s.created)),
          el("span", null, "активен " + ago(s.last_seen)),
        ),
      );
      var ops = el("div", "ops");
      if (!s.current) {
        var end = el("button", "btn sm ghost", "Завершить");
        end.addEventListener("click", function () {
          api("POST", "sessions/end", { id: s.id })
            .then(loadSessions)
            .catch(fail);
        });
        ops.appendChild(end);
      }
      box.appendChild(
        add(
          el("div", "row"),
          el(
            "span",
            "status" +
              (s.current || Date.now() - new Date(s.last_seen) < 120000
                ? " on"
                : ""),
          ),
          body,
          ops,
        ),
      );
    });
  }
  function loadSessions() {
    api("GET", "sessions").then(renderSessions).catch(quiet);
  }
  $("end-others").addEventListener("click", function () {
    if (!confirm("Выкинуть из админки все остальные браузеры?")) return;
    api("POST", "sessions/end-others").then(loadSessions).catch(fail);
  });
  $("ov-audit-all").addEventListener("click", function () {
    logQuery = "";
    $("log-filter").value = "";
    setTab("audit");
  });

  function refresh() {
    api("GET", "clients")
      .then(function (list) {
        renderClients(list);
        return api("GET", "overview");
      })
      .then(renderOverview)
      .catch(quiet);
    if (view === "devices") refreshPeople();
    if (view === "log") loadLog();
    if (view === "overview")
      api("GET", "audit?n=6").then(renderRecent).catch(quiet);
    if (view === "settings") loadSessions();
  }

  $("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("login-error").textContent = "";
    api("POST", "login", { password: $("password").value })
      .then(function () {
        $("password").value = "";
        showApp();
      })
      .catch(function (err) {
        $("login-error").textContent =
          err.message === "wrong password"
            ? "Неверный пароль"
            : err.message === "too many attempts"
              ? "Слишком много попыток, подожди 15 минут"
              : err.message;
      });
  });
  $("logout").addEventListener("click", function () {
    api("POST", "logout").finally(showLogin);
  });

  $("dev-new").addEventListener("click", function () {
    openAdd();
  });

  $("ban-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("ban-error").textContent = "";
    api("POST", "bans/add", {
      target: $("ban-target").value,
      reason: $("ban-reason").value,
    })
      .then(function () {
        $("ban-target").value = "";
        $("ban-reason").value = "";
        refresh();
      })
      .catch(function (err) {
        $("ban-error").textContent = err.message;
      });
  });

  function setFilter(f) {
    filter = f;
    document.querySelectorAll("#filter button").forEach(function (x) {
      x.setAttribute("aria-pressed", String(x.dataset.f === f));
    });
    renderClients(lastClients);
  }
  document.querySelectorAll("#filter button").forEach(function (b) {
    b.addEventListener("click", function () {
      setFilter(b.dataset.f);
    });
  });
  $("ov-alert-go").addEventListener("click", function () {
    setFilter("strangers");
  });

  $("strict").addEventListener("click", function () {
    var next = $("strict").getAttribute("aria-checked") !== "true";
    api("POST", "settings", { strict_proxy: next }).then(refresh).catch(fail);
  });

  var debounce = null;
  $("log-filter").addEventListener("input", function () {
    clearTimeout(debounce);
    debounce = setTimeout(function () {
      logQuery = $("log-filter").value.trim();
      loadLog();
    }, 250);
  });

  api("GET", "overview").then(showApp).catch(quiet);
})();
