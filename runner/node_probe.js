// Proves that `node` resolves and runs inside the confined test sandbox as the unprivileged user. Not a security probe (sandbox_probe.py is).
const net = require("net");
const bad = [];
if (typeof process.getuid === "function" && process.getuid() !== 65534) bad.push("not-nobody");
const fs = require("fs");
try { fs.writeFileSync("/usr/local/bin/.node-probe-" + process.pid, "x"); fs.unlinkSync("/usr/local/bin/.node-probe-" + process.pid); bad.push("writable:/usr/local/bin"); } catch (e) {}
const s = net.connect({ host: "1.1.1.1", port: 443, timeout: 3000 });
s.on("connect", () => { bad.push("network-reachable"); done(); }); s.on("error", () => done()); s.on("timeout", () => { s.destroy(); done(); });
function done() { if (done.d) return; done.d = true; console.log("node " + process.version + " uid " + process.getuid()); console.log(bad.length ? "PROBE_FAIL " + bad.join(",") : "PROBE_PASS"); process.exit(bad.length ? 1 : 0); }
