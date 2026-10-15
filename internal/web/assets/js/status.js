(function () {
  var $ = function (id) {
    return document.getElementById(id);
  };
  var protos = { doh: "DoH", dot: "DoT", doq: "DoQ", udp: "UDP", tcp: "TCP" };
  var levels = { low: "низкая", medium: "средняя", high: "высокая" };
  var statsTimer = null;

  function nonce() {
    var b = new Uint8Array(8);
    crypto.getRandomValues(b);
    return Array.prototype.map
      .call(b, function (x) {
        return ("0" + x.toString(16)).slice(-2);
      })
      .join("");
  }

  function show(kind, title, note) {
    $("page").className = kind;
    $("state").textContent = title;
    $("note").textContent = note;
    $("again").classList.toggle("hidden", kind === "wait");
  }

  function probe() {
    var n = nonce();
    new Image().src = "https://p-" + n + "." + location.hostname + "/api/pixel";
    var tries = 0;
    return new Promise(function (resolve) {
      function poll() {
        fetch("/api/probe?n=" + n, { cache: "no-store" })
          .then(function (r) {
            return r.json();
          })
          .then(function (d) {
            if (d.seen || ++tries >= 10) resolve(d);
            else setTimeout(poll, 500);
          })
          .catch(function () {
            if (++tries >= 10) resolve(null);
            else setTimeout(poll, 500);
          });
      }
      setTimeout(poll, 400);
    });
  }

  function duration(s) {
    var d = Math.floor(s / 86400),
      h = Math.floor((s % 86400) / 3600),
      m = Math.floor((s % 3600) / 60);
    return d ? d + " д " + h + " ч" : h ? h + " ч " + m + " мин" : m + " мин";
  }

  function stat(box, label, value) {
    var d = document.createElement("div"),
      dt = document.createElement("dt"),
      dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = value;
    d.appendChild(dt);
    d.appendChild(dd);
    box.appendChild(d);
  }

  function loadStats(proto) {
    fetch("/api/status", { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(function (s) {
        var box = $("stats");
        box.textContent = "";
        if (s.load >= 0)
          stat(box, "Нагрузка", s.load + "% · " + (levels[s.level] || ""));
        if (s.memory >= 0) stat(box, "Память", s.memory + "%");
        stat(box, "Соединений", String(s.conns));
        stat(box, "Без перезапуска", duration(s.uptime_sec));
        if (proto) stat(box, "Протокол", protos[proto] || proto);
        box.classList.remove("hidden");
      })
      .catch(function () {
        $("stats").classList.add("hidden");
      });
  }

  function check() {
    clearInterval(statsTimer);
    $("stats").classList.add("hidden");
    show("wait", "Проверяю…", "Смотрю, через какой DNS ходит это устройство.");
    probe().then(function (d) {
      if (d && d.seen) {
        show("ok", "Работает", "DNS этого устройства идёт через ReDNS.");
        loadStats(d.proto);
        statsTimer = setInterval(function () {
          if (!document.hidden) loadStats(d.proto);
        }, 10000);
      } else if (d) {
        show(
          "bad",
          "Не работает",
          "Это устройство ходит мимо этого DNS. Проверь, что профиль установлен, а VPN и Частный узел iCloud выключены.",
        );
      } else {
        show("bad", "Нет ответа", "Сервер не ответил на проверку.");
      }
    });
  }

  $("again").addEventListener("click", check);
  check();
})();
