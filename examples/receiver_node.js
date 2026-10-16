// Пример приёмника webhook-алертов FideVisio с проверкой подписи.
//
// Запуск:
//   FIDEVISIO_WEBHOOK_SECRET=<секрет канала> node receiver_node.js
//
// Секрет — значение `webhook_secret` канала в настройках FideVisio. Подпись
// считается как HMAC-SHA256 от сырых байт тела запроса, заголовок `X-Signature`
// имеет вид `sha256=<hex>`.

import http from "node:http";
import crypto from "node:crypto";

const SECRET = process.env.FIDEVISIO_WEBHOOK_SECRET;
if (!SECRET) {
  throw new Error("FIDEVISIO_WEBHOOK_SECRET is not set");
}
const PORT = 8080;

http
  .createServer((req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }

    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      const expected =
        "sha256=" + crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
      const got = req.headers["x-signature"] || "";

      const ok =
        expected.length === got.length &&
        crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(got));
      if (!ok) {
        res.writeHead(401).end();
        return;
      }

      const { event } = JSON.parse(raw.toString("utf8"));
      console.log(
        `${event.event_type}: ${event.monitor_name} — ${
          event.error_detail || "ok"
        }`
      );
      res.writeHead(200).end("ok");
    });
  })
  .listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
