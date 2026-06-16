# Demo assets

Two companion pieces for the launch — the "make the invisible decision visible" visuals
described in the blog plan. Both lead with the same beat: a token minted for one request,
the body altered, and the canonical hash diverging from what was authorized.

## 1. Terminal recording — `ext-authz-story.gif` / `.mp4`

The real CLI, recorded: `ext-authz-demo demo --story` walked one scenario at a time, in
color, all eleven verdicts ending on "11 scenarios, all as expected." This is the "it really
runs" proof — every hash, latency, and reason code is genuine output.

![ext-authz story-mode recording](ext-authz-story.gif)

`ext-authz-story.mp4` is the smaller, higher-quality version for a blog `<video>` or a
slide. Regenerate either from the recipe (run from the repo root):

```bash
cargo build -p ext-authz-demo            # capture the demo, not the compile
vhs demo/ext-authz-story.tape            # writes ext-authz-story.gif and .mp4
```

The recording needs a real terminal: `--story` only emits ANSI color on a TTY, so the
colors come from the recorder (VHS), not from piping the output to a file.

## 2. Interactive visual — `index.html`

A self-contained, dependency-free interactive: pick a scenario and watch the request flow
through the pipeline, the verifier cascade decide, and the audit line appear. The
standout beat is **Body changed** — the request's canonical hash diverges from the one
the token was minted for, side by side, the visual proof that the decision binds the
bytes that egress.

It contains the egress pipeline (`agent → L7 policy → Privacy Guard → ext-authz →
credential → upstream`, stopping at `ext-authz` on a deny), six of the eleven demo scenarios, the
verifier cascade with the failing step highlighted, the verdict (reason code, HTTP
status, sub-ms/low-ms latency), the digest-only audit event, and a light/dark toggle
(light reads well inline in a blog; dark projects well in a talk). Every value shown is
real output captured from `cargo run --bin ext-authz-demo -- demo`.

### Viewing it

No build step, no external dependencies — just open the file:

```bash
open demo/index.html                                  # macOS (xdg-open on Linux)
python3 -m http.server 4317 --directory demo          # or over http, then visit :4317
```

### Using it

- **Blog:** embed with `<iframe src="…/index.html" style="width:100%;height:720px;border:0">`,
  or screen-capture the allow → body-changed transition as an animated still.
- **Keynote:** open full-screen, toggle to dark, and click through the scenarios live —
  lead with "Body changed" to land intent binding in one frame.
