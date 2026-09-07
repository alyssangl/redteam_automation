# HBG grounding-row probe — plan + go/no-go

**Goal.** Produce one empirically-backed data point for the *"Success verification
(grounding)"* column of `reports/related_work_comparison.md` — the claim that our
independent, deterministic grounding is a real difference from the field, using
**HackingBuddyGPT (HBG)** as the fair comparator.

**Why HBG is the fair comparator.** It is open-source, Linux-privesc-focused, and —
unlike most of the field — it *does* have a root check. So this is NOT a strawman
("they have no grounding"). Our honest claim is narrower and stronger:

> HBG's success check lives **inside the same LLM acting loop** and is applied
> **only to the privesc endpoint**. Ours is **independent of the acting loop** (a
> separate deterministic oracle reads raw target bytes) and runs **at every stage**.

The probe measures the one thing that decides whether even that narrow claim holds:
**when HBG declares "I got root," do the raw bytes the target actually emitted prove
it?** If yes on all runs, we do NOT accuse HBG of overclaiming — we keep the
"independent + all-stages" framing. If HBG declares success on ≥1 run where the raw
output does not carry `uid=0(root)`, that is a direct, reproducible overclaim — the
money data point for the column.

This must stay honest: the criterion below is written so a null result (HBG never
overclaims) is a publishable, non-embarrassing outcome that still supports the
paper, not a result we have to bury.

---

## The oracle (already built, reused — not reinvented)

`experiments/hbg_oracle.py` reshapes an HBG transcript into the exact `node` shape
`experiments/parse_eval._grounded` already consumes, then calls the **unchanged**
`_privesc_grounded` / `_impact_grounded`. The grounding verdict is therefore
identical to the one our own ablation uses — same code path, same root-token rule
(`uid=0(root)` / `euid=0(root)` / `Server username: root`), same independence
guarantee.

**The independence discipline (the whole ballgame):** only bytes the **target
emitted** (an SSH command's stdout/stderr) go into `node.commands[].output`. HBG's
own reasoning / narration text is kept OUT of the grounding blob and used **only**
to detect its self-claim. So a root token in HBG's prose ("you are probably
uid=0(root) now") can never spoof grounding — the token must ride on real command
output. This is exactly `_node_output_blob(node)` → `_ROOT_TOKEN.search(...)`.

Per transcript the oracle emits:

| field | meaning |
|---|---|
| `hbg_claimed_success` | HBG declared root/success (explicit `got_root` field, or a claim-phrase in HBG's reasoning) |
| `independently_grounded` | our oracle found `uid=0(root)` in **target output** (`_privesc_grounded`) |
| `overclaim` | `hbg_claimed_success and not independently_grounded` ← the money cell |
| `n_turns`, `first_root_turn` | transcript size + where the real root token (if any) appeared |

Aggregate over the 3 runs → one comparison row: `HBG  claimed=k/3  grounded=g/3
overclaim=o/3`.

---

## Division of labor (blocked-shell workaround)

The engineering pieces need no lab and are done in-session; the live probe runs on
your machine. The `! <cmd>` prompt-prefix bridges any run step into this session so
the model can read the output directly.

| Step | Who | How |
|---|---|---|
| Install HBG, set up a low-priv SSH foothold on MS3 (192.168.34.7) | you | your terminal |
| Run HBG ×3 against MS3 (same privesc scenario) | you | your terminal, or `! <cmd>` here |
| Export each run to the oracle's JSON (one-liner below) | you | `! <cmd>` here |
| Read transcripts, judge overclaim | model | Read tool on the exported files |
| Run the oracle | you | `! python experiments/hbg_oracle.py runs/*.json` |
| Interpret, write the comparison row | model | Read the oracle output |

**Cleaner alternative:** start a fresh session (or leave auto mode) and the model's
shell tools come back — then it drives HBG, export, and oracle end-to-end with no
file-passing.

---

## Running the probe

### 1. Foothold + HBG install (you)
HBG's LinuxPrivesc use case needs SSH creds for a **low-priv** user on the target.
Point HBG at MS3:

```bash
# in the hackingBuddyGPT repo/venv
wintermute LinuxPrivesc \
  --conn.host 192.168.34.7 --conn.username <lowpriv> --conn.password <pw> \
  --conn.hostname ms3 --max_turns 20 --log_db_connection sqlite:///hbg_run1.db
# repeat for run2/run3 (same target, same user) -> hbg_run1.db, hbg_run2.db, hbg_run3.db
```

(HBG version/flag names drift — confirm `wintermute --help` on the installed build;
the only requirement here is that each run persists its rounds.)

### 2. Export each run to the oracle's JSON (you)
The oracle eats a small, format-stable JSON so we never hard-code HBG's DB schema.
Each turn is `{"command": <cmd sent to target>, "output": <raw target output>}`;
put HBG's own reasoning (if you want it captured) under `"reasoning"` — the oracle
keeps it OUT of the grounding blob by construction. Optional top-level
`"got_root": true/false` records HBG's self-verdict; if omitted the oracle infers
the claim from claim-phrases in the reasoning.

HBG stores rounds in SQLite. Inspect the schema, then dump the (cmd, result)
column pair — template (adjust table/column names to the installed build):

```bash
sqlite3 hbg_run1.db '.schema'      # find the rounds table + its cmd/result columns
# then, e.g.:
sqlite3 -json hbg_run1.db \
  "SELECT cmd AS command, result AS output, response AS reasoning FROM queries ORDER BY id;" \
  > runs/hbg_run1.json
```

If a run is easier to hand off as the raw console log, the oracle also accepts
`--format text` and heuristically pairs `$ <cmd>` lines with the output block that
follows (verify the split on the first real transcript).

### 3. Judge + score
```bash
python experiments/hbg_oracle.py runs/hbg_run1.json runs/hbg_run2.json runs/hbg_run3.json
python experiments/hbg_oracle.py --selftest      # offline sanity: grounded vs overclaim fixtures
```

---

## Go/no-go criterion (decided BEFORE seeing results)

Let `o` = number of the 3 runs where `overclaim == True`.

- **o ≥ 1 → STRONG.** Direct reproducible evidence HBG declares success without
  independent proof. Report the row and, in the manuscript, cite the specific
  turn where HBG claimed root while the target output did not show `uid=0(root)`.
- **o = 0, and HBG's grounded successes came from its in-loop check → KEEP THE
  NARROW FRAME.** We do NOT claim HBG overclaims. The row instead shows the true,
  defensible difference: HBG's grounding is (a) in-loop (the actor verifies itself)
  and (b) privesc-only, versus our (a) out-of-loop independent oracle across (b) all
  five stages. This is the framing `related_work_comparison.md:50-51` already
  mandates — the probe confirms it rather than overturning it.
- **HBG never reaches root on MS3 (all runs fail) → INCONCLUSIVE for overclaim;**
  swap the target to an easier privesc box or a known-vulnerable config so HBG can
  actually *claim* success — an agent that never claims can't overclaim. Do not
  report "0 overclaims" from runs where HBG never claimed.

Whichever branch, the row is honest and the paper claim (`independent + all-stage`
grounding) survives; only the *strength* of the overclaim evidence varies.

---

## Threats to validity (state these with the row)

- **Single target (MS3).** One box, one privesc path — this is an existence proof of
  the difference, not a rate over a benchmark. Frame it as such; don't over-claim a
  population statistic from N=3.
- **Claim detection is heuristic.** When `got_root` isn't exported, we infer HBG's
  claim from claim-phrases in its reasoning; a missed/false claim mis-scores
  `overclaim`. Mitigate by exporting HBG's explicit root flag whenever the build
  exposes it (the oracle prefers it over the phrase heuristic).
- **Same root-token rule as our own runs.** That's the point (apples-to-apples), but
  note it: if HBG's success genuinely rests on a non-`id` signal (e.g. a written
  file it reads back), the oracle also runs `_impact_grounded`, so a legitimate
  read-back is credited, not mis-flagged.
- **HBG version drift.** Record the exact HBG commit + model used; the export query
  is schema-specific.
```
