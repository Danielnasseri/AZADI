/* Azadi engine: browser-side heuristic scanner (parser -> function IR -> rules). MIT. */
(function (g) {
'use strict';
const SINK = /\b_?(?:mint|mintTo|mint_to|mint_to_checked|mint_tokens|mint_and_transfer|release|releaseTo)\s*(?:<[^>]*>)?\s*\(|\bMintTo\b|coin::mint|token::mint_to/;
const SARG = /_?(?:mint|mintTo|mint_to|mint_tokens|release|releaseTo)\s*\(([^)]*)\)/;
const VAL = /verif|proof|attest|ecrecover|ECDSA|recover|signature|merkle|threshold|quorum|ed25519|secp256k1|multisig|validate|spv|check_sig/i;
const AC = {
  sol: /\bonly[A-Z]\w*|\bauth\b|requiresAuth|\bhasRole\(|_checkOwner|_checkRole|msg\.sender\s*[!=]=|==\s*msg\.sender|\binitializer\b/,
  rs: /is_signer|\bSigner\b|has_one|require_keys_eq|require_eq|\.owner\s*[!=]=|assert_signer|constraint\s*=|key\(\)\s*==/,
  move: /Cap\b|_cap\b|signer::address_of|is_admin|assert_admin|tx_context::sender|ctx\.sender\(\)/
};
const MARK = /(processed|consumed|used|executed|spent|seen|claimed|completed|finalized)\w*\s*(\[[^\]]*\])?\s*=|\.insert\(|table::add|vec_set::insert|dynamic_field::add|bitmap|nonces?\w*\s*(\[[^\]]*\])?\s*(\+\+|\+=|=[^=])|is_processed|mark_\w+/i;
const RX = {
  sol: /function\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{/g,
  rs: /fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)([^{;]*)\{/g,
  move: /fun\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)([^{;]*)\{/g
};
const strip = t => t.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' ')).replace(/\/\/[^\n]*/g, m => ' '.repeat(m.length));
const detect = (n, t) => /\.sol$/i.test(n) ? 'sol' : /\.rs$/i.test(n) ? 'rs' : /\.move$/i.test(n) ? 'move'
  : /pragma solidity|\bcontract\s+\w+/.test(t) ? 'sol' : /^\s*module\s+[\w:]+/m.test(t) || /\bpublic\s+(entry\s+)?fun\b/.test(t) ? 'move' : /\bfn\s+\w+|#\[program\]/.test(t) ? 'rs' : 'sol';
const pn = f => f.params.split(',').map(s => s.trim()).filter(Boolean)
  .map(s => f.lang === 'sol' ? s.split(/\s+/).pop() : s.split(':')[0].replace(/^(mut|&|\s)+/, '').trim());
const I = (f, level, msg) => ({ fn: f.name, file: f.file, line: f.line, level, msg });

function extract(file) {
  const src = file.text, re = new RegExp(RX[file.lang].source, 'g'), out = [];
  let m;
  while ((m = re.exec(src))) {
    let i = re.lastIndex, d = 1;
    while (i < src.length && d > 0) { const ch = src[i++]; if (ch === '{') d++; else if (ch === '}') d--; }
    const pre = src.slice(Math.max(src.lastIndexOf('\n', m.index), src.lastIndexOf('}', m.index - 1), src.lastIndexOf(';', m.index - 1)) + 1, m.index);
    const exposed = file.lang === 'sol' ? !/\b(internal|private|view|pure)\b/.test(m[3])
      : file.lang === 'rs' ? /\bpub\b(?!\s*\()/.test(pre)
      : (/\bentry\b/.test(pre) || (/\bpublic\b/.test(pre) && !/public\s*\(/.test(pre)));
    out.push({ name: m[1], params: m[2], head: pre + m[0].slice(0, -1), body: src.slice(re.lastIndex, i),
      file: file.name, lang: file.lang, exposed, line: src.slice(0, m.index).split('\n').length, src });
    re.lastIndex = i;
  }
  return out;
}

const ac = f => AC[f.lang].test(f.head + f.body);
const sinkFns = c => c.fns.filter(f => f.exposed && SINK.test(f.body));
const fileHas = (f, r) => r.test(f.src);

const CHECKS = [
{ id: 'ENTRY', t: 'Mint / release authorization', inv: 'Mint authorization = authorized bridge', crit: 1, needSink: 1,
  fix: 'Gate every mint/release behind a bridge-only role or capability and verify a proof inside the same path.',
  ok: 'Every exposed mint/release path has access control or in-path verification.',
  run: c => sinkFns(c).filter(f => !ac(f) && !VAL.test(f.body)).map(f => I(f, 1, 'Exposed mint/release with no access control and no proof/signature check.')) },
{ id: 'BIND', t: 'Amount & recipient binding', inv: 'Minted amount = verified amount; recipient = authenticated recipient', needSink: 1,
  fix: 'Derive the amount from the verified BTC output and include amount, recipient, chain and contract in the signed/hashed payload.',
  ok: 'Caller-supplied amount and recipient appear inside verified data.',
  run: c => sinkFns(c).filter(f => VAL.test(f.body)).flatMap(f => {
    const bad = pn(f).filter(n => /^_?(amount|value|sats?|qty|to|recipient|receiver|account|user|dst|dest\w*)$/i.test(n))
      .filter(n => !new RegExp('(keccak256|sha256|hash|encode\\w*|digest|verify\\w*|recover\\w*)[^;]*\\b' + n + '\\b', 'i').test(f.body));
    return bad.length ? [I(f, 2, 'Caller-supplied ' + bad.join(', ') + ' is not visibly bound to the verified proof/hash.')] : [];
  }) },
{ id: 'REPLAY', t: 'Replay & double mint', inv: 'One deposit = at most one mint; one message = at most one execution', crit: 1, needSink: 1,
  fix: 'Mark the BTC txid+vout / message id as consumed before minting, and revert if already consumed.',
  ok: 'Consumed-marker logic found next to mint/release.',
  run: c => sinkFns(c).filter(f => (VAL.test(f.body) || pn(f).some(n => /tx|nonce|id|hash|message|deposit/i.test(n))) && !MARK.test(f.body))
    .map(f => I(f, ac(f) ? 2 : 1, 'No consumed-marker (processed/used/nonce) found before mint/release; the same proof may be reusable.')) },
{ id: 'SOURCE', t: 'Source chain, peer & endpoint identity', inv: 'Source chain/contract = expected source', needSink: 0,
  fix: 'Check msg.sender is the endpoint/router and compare origin chain and sender against a configured peer.',
  ok: 'Message handlers validate origin and peer.',
  run: c => c.fns.filter(f => /^_?(lzReceive|ccipReceive|nonblockingLzReceive|handle|receive_?message|receive_?msg|execute_?message|process_?message|finalize_?deposit|on_?message)$/i.test(f.name)).flatMap(f => {
    const o = [];
    if (f.lang === 'sol' && f.exposed && !/endpoint|router|onlyEndpoint|msg\.sender\s*[!=]=|==\s*msg\.sender/i.test(f.head + f.body)) o.push(I(f, 1, 'Message receiver does not check that the caller is the trusted endpoint/router.'));
    if (!/(peers?|trusted_?remote|expected_?source|srcEid|origin|source_?chain|source_?contract|remote|emitter|sender)\w*[^;\n]*(==|!=|\[|contains|eq|assert|require)|require_keys_eq|assert_eq/i.test(f.body)) o.push(I(f, VAL.test(f.body) ? 2 : 1, 'No comparison of source chain / source contract against a configured peer.'));
    return o; }) },
{ id: 'DOMAIN', t: 'Signature domain separation', inv: 'Signature bound to chain, contract, nonce, payload', needSink: 0,
  fix: 'Use EIP-712 (or equivalent): include chain id, verifying contract, nonce and full payload; use a vetted ECDSA library.',
  ok: 'Signature checks include domain data and replay protection.',
  run: c => c.fns.filter(f => /ecrecover|ECDSA\.|\.recover\(|SignatureChecker|ed25519_verify|verify_signature|secp256k1|ed25519::/i.test(f.body)).flatMap(f => {
    const o = [], ctx = f.body + (f.lang === 'sol' ? f.src : '');
    const miss = [];
    if (!/chainid|chain_id|DOMAIN_SEPARATOR|_hashTypedData|EIP712|address\(this\)|program_id|domain/i.test(ctx)) miss.push('chain/contract domain');
    if (!/nonce|deadline|expir|used|processed/i.test(ctx)) miss.push('nonce/expiry');
    if (miss.length) o.push(I(f, 2, 'Signature check without ' + miss.join(' and ') + ': a valid signature may be accepted on the wrong chain or twice.'));
    if (/ecrecover\(/.test(f.body) && !/address\(0\)/.test(f.body)) o.push(I(f, 2, 'ecrecover result is not checked against the zero address.'));
    return o; }) },
{ id: 'BACKING', t: 'Reserve / backing invariant', inv: 'Minted BTC <= verified BTC backing', needSink: 1,
  fix: 'Enforce supply <= verified reserve on-chain (or document the off-chain enforcer as a trust boundary).',
  ok: 'Reserve/backing logic is present. Confirm it runs before every mint.',
  run: c => { const f = sinkFns(c)[0]; return f && !c.files.some(x => /reserve|backing|backed|proofOfReserve|total_?locked|custody|max_?supply|supplyCap/i.test(x.text)) ? [I(f, 3, 'No on-chain backing/reserve invariant is visible. If enforced off-chain, that service is a trust boundary.')] : []; } },
{ id: 'FINAL', t: 'Finality & reorg', inv: 'Mint only after sufficient BTC finality', needSink: 1,
  fix: 'Require a minimum confirmation count / block depth in the verified proof before minting.',
  ok: 'Confirmation or finality logic found.',
  run: c => { const f = sinkFns(c)[0]; return f && c.files.some(x => /btc|bitcoin|txid|satoshi|utxo|sats/i.test(x.text)) && !c.files.some(x => /confirm|finality|finalized|depth|min_?conf|reorg/i.test(x.text)) ? [I(f, 2, 'BTC-related mint with no confirmation/finality requirement found.')] : []; } },
{ id: 'REDEEM', t: 'Burn to BTC withdrawal binding', inv: 'Burn amount = withdrawal amount', needSink: 0,
  fix: 'Emit a request that binds burned amount, BTC recipient script and a unique withdrawal id; make settlement replay-proof.',
  ok: 'Burn paths emit a request record.',
  run: c => c.fns.filter(f => f.exposed && /\b_?(burn|burnFrom|burn_from)\w*\s*\(|coin::burn|token::burn/.test(f.body)).flatMap(f => {
    const o = [];
    if (!/emit\s|event::emit|emit_event|msg!\(|emit!\(/.test(f.body)) o.push(I(f, 2, 'Burn without an event/request record: off-chain settlement cannot bind it to a BTC payout.'));
    if (!/btc|bitcoin|script|recipient|withdraw/i.test(f.params + f.body)) o.push(I(f, 2, 'Burn is not bound to a BTC recipient or withdrawal id.'));
    return o; }) },
{ id: 'ORACLE', t: 'Oracle & price integrity', inv: 'Collateral price reflects real backing', needSink: 0,
  fix: 'Check updatedAt/heartbeat, use TWAP or multiple sources, and never price collateral from a thin spot pool.',
  ok: 'No unsafe oracle usage detected.',
  run: c => c.fns.flatMap(f => {
    const o = [];
    if (/latestRoundData\s*\(/.test(f.body) && !/updatedAt|answeredInRound|stale|heartbeat/i.test(f.body)) o.push(I(f, 2, 'Chainlink price read without a staleness check.'));
    if (/getReserves\s*\(|slot0\s*\(/.test(f.body)) o.push(I(f, 2, 'Spot pool price used; manipulable with low liquidity.'));
    if (/get_price_unchecked|get_current_price/.test(f.body)) o.push(I(f, 2, 'Oracle price read without a freshness check.'));
    return o; }) },
{ id: 'CONFIG', t: 'Privileged configuration & upgrades', inv: 'Only admin can change peer, minter, oracle, limits, implementation', crit: 1, needSink: 0,
  fix: 'Restrict configuration and upgrade functions to a multisig/timelock role.',
  ok: 'Configuration and upgrade functions are access-controlled. (Upgradeability itself is not a finding.)',
  run: c => c.fns.filter(f => f.exposed && /^(set|update|change|add|remove|grant|revoke|upgrade|migrate)_?\w*(peer|trusted|minter|burner|oracle|bridge|vault|rate|limit|owner|admin|guardian|authority|dvn|executor|implementation|role|cap)\w*$|^upgrade\w*$|^transfer_?(owner|admin|authority)\w*$/i.test(f.name) && !ac(f))
    .map(f => I(f, 1, 'Configuration/upgrade function is callable without access control.')) },
{ id: 'RATE', t: 'Rate limits & damage containment', inv: 'Blast radius is bounded', needSink: 1,
  fix: 'Add mint/burn caps and a pause switch. These limit damage; they do not fix logic bugs.',
  ok: 'Containment controls found (they reduce blast radius; they are not a fix).',
  run: c => { const f = sinkFns(c)[0]; return f && !c.files.some(x => /rate_?limit|daily_?limit|mint_?limit|mint_?cap|max_?mint|supply_?cap|whenNotPaused|Pausable|paused|circuit_?breaker|pause/i.test(x.text)) ? [I(f, 3, 'No rate limit or pause switch found.')] : []; } },
{ id: 'SOL', t: 'Solidity-specific', inv: 'Safe external calls and authentication', only: 'sol', needSink: 0,
  fix: 'Use msg.sender, checks-effects-interactions or nonReentrant, SafeERC20, and never delegatecall to caller-chosen targets.',
  ok: 'No tx.origin, delegatecall, call-ordering or unchecked-transfer issues detected.',
  run: c => c.fns.filter(f => f.lang === 'sol').flatMap(f => {
    const o = [];
    if (/tx\.origin\s*[!=]=|==\s*tx\.origin/.test(f.body)) o.push(I(f, 2, 'tx.origin used for authentication.'));
    pn(f).forEach(n => { if (f.exposed && new RegExp('\\b' + n + '\\b\\s*\\.delegatecall|delegatecall\\([^)]*\\b' + n + '\\b').test(f.body) && !ac(f)) o.push(I(f, 2, 'delegatecall to a caller-supplied target.')); });
    const k = f.body.search(/\.call\{|\.call\(|\.send\(|safeTransfer\(/);
    if (k >= 0 && !/nonReentrant/.test(f.head) && /(\w+)(\[[^\]]*\])+\s*(-=|\+=|=[^=])/.test(f.body.slice(k + 5))) o.push(I(f, 2, 'External call occurs before a state update (reentrancy risk).'));
    f.body.split('\n').forEach(l => { if (/\.transfer\([^,)]+,[^)]*\)|\.transferFrom\(/.test(l) && !/require|safe|if\s*\(|bool|=\s/.test(l)) o.push(I(f, 3, 'ERC20 transfer return value ignored.')); });
    return o; }) },
{ id: 'RUST', t: 'Rust / Solana account validation', inv: 'Signer = expected authority; account = expected program', only: 'rs', needSink: 0,
  fix: 'Use typed Anchor accounts or explicitly check signer, owner and program id; use checked arithmetic.',
  ok: 'No unchecked accounts, arbitrary CPI or unchecked arithmetic detected.',
  run: c => c.fns.filter(f => f.lang === 'rs').flatMap(f => {
    const o = [], all = f.head + f.body;
    if (/AccountInfo|UncheckedAccount/.test(f.params) && !/is_signer|owner|has_one|key\(\)\s*==|require_keys_eq|check_id/.test(all)) o.push(I(f, 2, 'Untyped account with no signer/owner/key check.'));
    if (/remaining_accounts/.test(f.body) && !/key\(\)\s*==|require_keys_eq|owner/.test(f.body)) o.push(I(f, 2, 'remaining_accounts used without validation.'));
    if (/\binvoke(_signed)?\s*\(/.test(f.body) && !/program_id|key\(\)\s*==|require_keys_eq|check_id|check_program/.test(f.body)) o.push(I(f, 2, 'CPI without verifying the target program id.'));
    if (/(amount|balance|supply|total|fee)\w*\s*(\+=|-=|\*=)|(amount|balance|supply|total)\w*\s+[+\-*]\s+\w/i.test(f.body) && !/checked_|saturating_/.test(f.body) && !/overflow-checks/.test(f.src)) o.push(I(f, 2, 'Unchecked arithmetic on amounts.'));
    return o; }) },
{ id: 'MOVE', t: 'Move capability safety', inv: 'Capability never leaks to an untrusted caller', only: 'move', needSink: 0,
  fix: 'Give capability structs neither copy nor drop; never return or share them from public functions.',
  ok: 'No capability leakage patterns detected.',
  run: c => c.files.filter(x => x.lang === 'move').flatMap(x => {
    const o = [], fake = n => ({ name: n, file: x.name, line: 1 });
    (x.text.match(/struct\s+\w*Cap\w*\s+has\s+[^{]*/g) || []).forEach(s => { if (/\b(copy|drop)\b/.test(s)) o.push(I(fake(s.split(/\s+/)[1]), 1, 'Capability struct has copy/drop and can be duplicated or discarded.')); });
    (x.text.match(/public\s+(entry\s+)?fun\s+\w+[^{]*:\s*\w*Cap\b[^{]*/g) || []).forEach(s => o.push(I(fake(s.match(/fun\s+(\w+)/)[1]), 2, 'Public function returns a capability.')));
    if (/share_object\([^)]*Cap/.test(x.text)) o.push(I(fake('share_object'), 2, 'A capability object is shared publicly.'));
    return o; }) }
];

async function scan(files, onStep) {
  files.forEach(f => { f.lang = f.lang || detect(f.name, f.text); f.text = strip(f.text); });
  const ctx = { files, fns: files.flatMap(extract) };
  ctx.hasSink = ctx.fns.some(f => SINK.test(f.body));
  const langs = [...new Set(files.map(f => f.lang))];
  const checks = [], findings = [];
  for (const ck of CHECKS) {
    if (onStep) onStep(ck.t);
    await new Promise(r => setTimeout(r, 120));
    let status, issues = [];
    if ((ck.only && !langs.includes(ck.only)) || (ck.needSink && !ctx.hasSink)) status = 'na';
    else { issues = ck.run(ctx); status = !issues.length ? 'good' : issues.some(i => i.level < 3) ? 'bad' : 'note'; }
    checks.push({ id: ck.id, title: ck.t, status, issues, ok: ck.ok, fix: ck.fix });
    issues.forEach(i => findings.push({
      id: 'AZ-' + String(findings.length + 1).padStart(3, '0'), title: ck.t,
      severity: i.level === 1 ? (ck.crit ? 'CRITICAL' : 'HIGH') : i.level === 2 ? 'MEDIUM' : 'INFO',
      confidence: ['', 'Level 1: likely vulnerability (heuristic)', 'Level 2: suspicious pattern', 'Level 3: architecture note'][i.level],
      file: i.file, function: i.fn, line: i.line, evidence: i.msg, recommendedFix: ck.fix, relatedInvariant: ck.inv }));
  }
  return { langs, files: files.length, functions: ctx.fns.length, checks, findings };
}
const api = { scan, detect, extract, CHECKS };
if (typeof module !== 'undefined') module.exports = api; else g.Azadi = api;
})(typeof window !== 'undefined' ? window : globalThis);
