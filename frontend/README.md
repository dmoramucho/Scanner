# Frontend — the analyst UI

The web app the analyst works in. P20 builds its backbone: the shared component system for the
three distinctions (confidence, management state, fact vs AI) that every screen reuses. The
real screens arrive in P21/P22.

```bash
npm install
npm run dev       # the component gallery on http://127.0.0.1:5173
npm run check     # lint + format + type-check + tests, the way CI would
```

`npm run dev` proxies `/api` to `http://127.0.0.1:8000`, so run the backend alongside it:

```bash
cd .. && uv run uvicorn api.main:app --host 127.0.0.1 --port 8000
```

## What is here

| Path | What it holds |
|---|---|
| `src/types/api.ts` | The API contract in TypeScript — the vocabulary everything else speaks |
| `src/theme/tokens.css` | Every colour and size, defined once. No component carries a hex |
| `src/components/treatments.ts` | Every contract value → its label, tokens and explanation |
| `src/components/` | The badges and panels. Four-line components; the decisions are above |
| `src/gallery/` | Every component in every state — the consistency check, made visible |
| `src/mock/fixtures.ts` | Typed mock data. Deleted in P21 when the API arrives |

## The rules this layer holds itself to

- **One dictionary.** Each distinction is a `Record<Union, Treatment>` keyed by the API's own
  union, so a state added to the backend is a compile error rather than a blank badge.
- **One palette.** A test fails the build if a component source contains a literal colour, or
  references a token the theme does not define.
- **One signal shouts.** KEV is the only badge with a solid fill — if everything is red,
  nothing is urgent.
- **AI content cannot be rendered as a fact.** `AiPanel` requires citations, and the type is a
  non-empty tuple: an ungrounded insight does not compile.
- **Unknown is never dressed as shadow IT**, and an unmapped VLAN reads as *unknown* rather
  than as a plausible guess.

See `docs/adr/0018-frontend-stack-and-component-system.md` for why, and what was considered
instead.
