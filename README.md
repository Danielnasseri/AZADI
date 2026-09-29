# Azadi
Free, open-source BTC-backed bridge security scanner (Solidity, Rust, Move). Runs 100% in the browser; no server, no upload. Built by DanielNasseri to help strengthen blockchain network security.

## Launch on GitHub
1. Create a repo, push these files to `main`.
2. Settings > Pages > Source: **GitHub Actions** (the included workflow deploys it).
3. Set the `AboutProject` link: edit the `href="#"` on `id="about"` in `index.html`.

## What it does
Parses functions into a small IR and runs rules for the "valid entry != valid state transition" path: mint authorization, amount/recipient binding, replay, source/peer identity, signature domain separation, backing, finality, burn-to-withdrawal binding, oracle, config/upgrade access, rate limits, plus Solidity / Rust / Move specifics.

## Limits (v1)
Regex/brace-level heuristics, not a full AST/CFG/taint engine. Level 1 = likely, Level 2 = suspicious, Level 3 = architecture note. Not a substitute for manual audit. Roadmap: real parsers (tree-sitter), CFG + taint, cross-contract call graph, deployment-config diffing.

License: MIT
