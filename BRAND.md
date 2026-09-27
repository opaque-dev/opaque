# Opaque — brand

The point of this file is that the next redesign starts from here instead of
from scratch. The first landing page carried a slogan that was lost when the
site moved to MkDocs, because it lived only in one HTML file on an unmerged
branch. It is written down now.

## The slogan

> **Secrets stay ███████. Agents stay powerful.**
> **Approve the work. Keep authority bounded.**

The first pair is the brand line, always two lines in that order. Line one
makes the promise and performs it: `secret` is present in the markup,
so screen readers and search engines read "Secrets stay secret", under a
redaction bar. Line two is why anyone tolerates line one: not to lock the
agent out, but to keep it useful without handing it values.

Do not paraphrase it into "Secrets stay hidden" or "Agents stay productive".
Do not use line one alone; half the slogan is an unfinished argument.

The second pair is a secondary line, run right after the brand line where
there's room: it names the mechanism (bounded agent work, see
[bounded-work.md](docs/bounded-work.md)), the brand line names the
guarantee. Alongside, never instead of.

Brand line: landing hero (`docs/overrides/home.html`), `README.md`,
`docs/index.md`, `site_description` in `mkdocs.yml`. Secondary line: runs
alongside it in `README.md` and `docs/index.md` only. Hero and meta
description stay brand-line-only; both need to stay short.

## The audience

Every external page names who this is for, early, in this frame:

> Platform and security teams whose developers already use AI coding
> agents. Today those teams either keep sensitive access away from the
> agent or watch its every move.

Three roles, always the same split. The **security or platform lead** owns
policy, custody, and the evidence trail. The **developer** hands the agent
real work, approves the exact scope once, and reads the receipt. The
**agent** finishes the task with operations, never plaintext. Category
statement, verbatim where the reader might mis-shelve us: *not another
secrets manager or agent framework. It decides what may pass between the
two you already have, and proves what did.*

Size is a journey, not a gate. Never qualify the audience by headcount;
say "start on one laptop; one signed policy governs a fleet." The
public core is Apache-2.0 and documentation is CC BY 4.0; link to the
licensing page for scope and third-party notices. Do not claim government, compliance certifications, or
a vertical: nothing shipped supports those claims. Do not pitch individual
hobbyist developers as the market. Where it lives: `#op-who` on the landing page, "Who It's For"
in `README.md`, the opening paragraph of `docs/index.md`.

## The voice

Write like the reference sites read (ArcBox, Oleander): short declarative
sentences, concrete nouns, real numbers, honest hedges stated flat. One
dash per section at most; prefer a period, comma, or colon. Never the
"not X, not Y, it's Z" cadence, chained appositives, or clever closers.
If a sentence works read aloud in one breath, keep it. If it needs the
dash to breathe, split it.

## The redaction motif

Redaction is the one visual idea. It appears in three forms, and nothing else
in the design competes with it:

| Form | Where | Class |
|---|---|---|
| Bar covering a word | Hero slogan | `.op-redacted` — the bar wipes across in 0.55s and stays |
| Word readable on a redaction ground | Emphasis in headings | `.op-redact` |
| `████` inline blocks | Terminal transcripts, prose | `.t-mask`, or literal block characters |

The bar is drawn in `--op-redact-bg`: warm cream on the graphite ground, near-
black on the paper ground: a censored document in both directions. It never
animates on `prefers-reduced-motion`; it is simply already there.

## Type and color

The tokens in `docs/stylesheets/extra.css` are the source of truth; this is the
short version.

- **Type:** Archivo (300/400/700) for everything, IBM Plex Mono for code,
  commands, and machine output. Headline tracking is negative (`-0.028em` at
  hero size), body is not.
- **Ground:** graphite `#0f1317` (dark) / warm paper `#f7f6f2` (light). Both are
  designed; neither is a fallback for the other.
- **Accent:** one amber "seal" — `#d9a544` on graphite, `#7a5504` on paper.
  Used for links, stage labels, and approval markers. If something needs a
  second accent, it usually needs less emphasis instead.
- **Semantic:** green reads as verified (`Audit chain intact`), never as
  decoration.

## Voice

- Lead with the threat model, not the feature list.
- Name the pipeline in its own terms: Policy → Approval → Execute → Sanitize →
  Audit.
- Never write "secure" without saying how, and never claim a guarantee the
  daemon does not enforce. The threat model is stated honestly on the site,
  including what session mode does *not* prevent. That honesty is the brand.
- Monospace for anything a machine reads: commands, config keys, refs, IDs.
