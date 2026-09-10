# handoff/ — the presentation package

Everything you need to **present** the GRAFT handover, in one place.

| File | What it is |
|---|---|
| `graft_talk.html` | The talk deck (10 slides). Open in a browser; theme-aware, has a print stylesheet. |
| `graft_talk.pdf` | The deck exported to PDF (one slide per landscape page) — hand this to the audience. |

## The newcomer-facing docs stay in the repo (not here)

Those are for the students to *read and use with the code*, so they live where the
code is — don't move them into this folder:

- `docs/ONBOARDING.md` — the source-verified code walkthrough (their first read).
- `HANDOFF.md` — lab operations + landmines.
- `docs/DESIGN_PHILOSOPHY.md` — why the system is shaped this way.
- `reports/graft_results_summary.md` — the results write-up the deck's numbers come from.

## Regenerating the PDF

The PDF is a render of `graft_talk.html`. To rebuild it after editing the deck
(headless Chrome, from the repo root):

```bash
chrome --headless=new --disable-gpu --no-pdf-header-footer \
  --run-all-compositor-stages-before-draw --virtual-time-budget=12000 \
  --print-to-pdf="handoff/graft_talk.pdf" \
  "file:///ABSOLUTE/PATH/TO/handoff/graft_talk.html"
```

(The deck's `@media print` block paginates it one slide per A4-landscape page and
forces the light palette so it prints on white.)
