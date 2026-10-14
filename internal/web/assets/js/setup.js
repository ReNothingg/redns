(function () {
  var $ = function (id) {
    return document.getElementById(id);
  };

  var tabs = document.querySelectorAll(".tabs button");
  function pick(t) {
    tabs.forEach(function (b) {
      b.setAttribute("aria-selected", b.dataset.t === t ? "true" : "false");
    });
    document.querySelectorAll(".panel").forEach(function (p) {
      p.classList.toggle("active", p.id === "p-" + t);
    });
  }
  tabs.forEach(function (b) {
    b.addEventListener("click", function () {
      pick(b.dataset.t);
    });
  });
  var ua = navigator.userAgent;
  var dev = /Android/.test(ua)
    ? "android"
    : /iPhone|iPad|iPod/.test(ua)
      ? "ios"
      : /Macintosh/.test(ua) && navigator.maxTouchPoints > 1
        ? "ios"
        : /Macintosh/.test(ua)
          ? "mac"
          : /Windows/.test(ua)
            ? "win"
            : null;
  if (dev) pick(dev);

  document.querySelectorAll("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var c = b.querySelector(".c");
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(b.dataset.copy).then(function () {
        b.classList.add("done");
        if (c) c.textContent = "Скопировано";
        setTimeout(function () {
          b.classList.remove("done");
          if (c) c.textContent = "Копировать";
        }, 1400);
      });
    });
  });

  function state(cls, title, hint) {
    $("state").className = "state " + cls;
    $("state-text").textContent =
      {
        ok: "DNS подключён",
        warn: "DNS не подключён",
        bad: "Сервер не ответил",
      }[cls] || "Проверка";
    $("st").textContent = title;
    $("hint").textContent = hint;
  }
  function fact(k, v) {
    var d = document.createElement("div"),
      dt = document.createElement("dt"),
      dd = document.createElement("dd");
    dt.textContent = k;
    dd.textContent = v;
    d.appendChild(dt);
    d.appendChild(dd);
    $("facts").appendChild(d);
  }
  function ago(s) {
    return s < 60
      ? s + " с назад"
      : s < 3600
        ? Math.round(s / 60) + " мин назад"
        : Math.round(s / 3600) + " ч назад";
  }
  var protos = { doh: "DoH", dot: "DoT", doq: "DoQ", udp: "UDP", tcp: "TCP" };

  fetch("/api/whoami", { cache: "no-store" })
    .then(function (r) {
      return r.json();
    })
    .then(function (w) {
      if (w.using_dns) {
        state(
          "ok",
          "Работает",
          "Запросы с этого устройства идут через ReDNS. Заблокированные сервисы открываются через сервер.",
        );
        fact("протокол", protos[w.proto] || w.proto);
        fact("запрос", ago(w.seconds_ago));
      } else {
        state(
          "warn",
          "Не подключено",
          "С этого IP запросов к ReDNS нет. Поставь профиль ниже и обнови страницу. Если включены VPN или Частный узел iCloud, DNS идёт мимо.",
        );
      }
      fact("ip", w.ip);
      if (!w.proxy_access) fact("прокси", "нет доступа");
    })
    .catch(function () {
      state(
        "bad",
        "Нет ответа",
        "Сервер не ответил на проверку. Обнови страницу через минуту.",
      );
    });

  var tb = $("tbtn");
  tb.addEventListener("click", function () {
    var total = 10 * 1048576,
      got = 0,
      t0 = performance.now(),
      last = t0,
      stalled = false;
    var bar = $("tbar"),
      res = $("tres"),
      warn = $("twarn"),
      big = $("tbig");
    tb.disabled = true;
    warn.style.display = "none";
    bar.style.width = "0";
    res.textContent = "Качаю…";
    var ctrl = new AbortController();
    var dog = setInterval(function () {
      if (performance.now() - last > 6000) {
        stalled = true;
        ctrl.abort();
        clearInterval(dog);
      }
    }, 500);
    function show(mbit) {
      big.textContent = mbit;
      var s = document.createElement("small");
      s.textContent = "Мбит/с";
      big.appendChild(s);
    }
    fetch("/api/test?mb=10", { cache: "no-store", signal: ctrl.signal })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        var rd = r.body.getReader();
        return (function pump() {
          return rd.read().then(function (x) {
            if (x.done) return;
            got += x.value.length;
            last = performance.now();
            bar.style.width =
              Math.min(100, (got / total) * 100).toFixed(1) + "%";
            var s = (last - t0) / 1000;
            if (s > 0.2) show(((got * 8) / s / 1e6).toFixed(1));
            return pump();
          });
        })();
      })
      .then(function () {
        var s = (performance.now() - t0) / 1000;
        show(((got * 8) / s / 1e6).toFixed(1));
        res.textContent =
          (got / 1048576).toFixed(0) + " МБ за " + s.toFixed(1) + " с";
      })
      .catch(function (e) {
        res.textContent = "Получено " + (got / 1024).toFixed(0) + " КБ";
        if (stalled) {
          warn.style.display = "block";
          warn.textContent =
            got < 64 * 1024
              ? "Загрузка встала на " +
                (got / 1024).toFixed(0) +
                " КБ. Так выглядит заморозка ТСПУ: подсеть хостера под фильтром, нужен VPS у другого провайдера."
              : "Загрузка остановилась на середине. Канал нестабилен, повтори тест.";
        } else if (String(e).indexOf("403") >= 0) {
          res.textContent =
            "Нет доступа: сначала подключи DNS на этом устройстве.";
        }
      })
      .finally(function () {
        clearInterval(dog);
        tb.disabled = false;
      });
  });
})();
