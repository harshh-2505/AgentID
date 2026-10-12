#!/usr/bin/env node
// AgentID policy tool.
//
//   node policy/cli.js check <file>                 parse + lint; exit 1 on errors
//   node policy/cli.js diff <old> <new>             semantic diff; exit 2 when anything widens (CI gate)
//   node policy/cli.js fmt <file>                   print the canonical form
//   node policy/cli.js issue <file> --principal key.json --agents agents.json
//                                                   sign the mandates, print them as JSON
//
// key.json is Principal.export(); agents.json maps names to dids ({ "ledgerline": "did:agentid:…" }).
// A subject that is already a did needs no mapping.

import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { parse, format, lint, diff, formatDiff, PolicyError } from './dsl.js';
import { Principal, isDid } from '../core/index.js';

const { positionals: [cmd, ...files], values: o } = parseArgs({
  allowPositionals: true,
  options: { principal: { type: 'string' }, agents: { type: 'string' }, json: { type: 'boolean' } },
});

const load = async (file) => {
  try {
    return parse(await readFile(file, 'utf8'));
  } catch (e) {
    if (e instanceof PolicyError) { console.error(`${file}:${e.message}`); process.exit(1); }
    throw e;
  }
};
const usage = () => { console.error('usage: cli.js check <file> | diff <old> <new> | fmt <file> | issue <file> --principal key.json --agents agents.json'); process.exit(64); };

switch (cmd) {
  case 'check': {
    if (files.length !== 1) usage();
    const specs = await load(files[0]);
    const warnings = lint(specs);
    if (o.json) console.log(JSON.stringify({ mandates: specs.length, warnings }, null, 2));
    else {
      for (const w of warnings) console.log(`warning [${w.code}] "${w.mandate}": ${w.message}`);
      console.log(`${files[0]}: ${specs.length} mandate(s), ${warnings.length} warning(s)`);
    }
    break;
  }
  case 'diff': {
    if (files.length !== 2) usage();
    const result = diff(await load(files[0]), await load(files[1]));
    console.log(o.json ? JSON.stringify(result, null, 2) : formatDiff(result));
    process.exitCode = result.widened ? 2 : 0;
    break;
  }
  case 'fmt': {
    if (files.length !== 1) usage();
    process.stdout.write(format(await load(files[0])));
    break;
  }
  case 'issue': {
    if (files.length !== 1 || !o.principal) usage();
    const specs = await load(files[0]);
    const principal = await Principal.restore(JSON.parse(await readFile(o.principal, 'utf8')));
    const agents = o.agents ? JSON.parse(await readFile(o.agents, 'utf8')) : {};
    const out = [];
    for (const { subject, ttlSec, ...spec } of specs) {
      const entry = agents[subject];
      const sub = isDid(subject) ? subject : typeof entry === 'string' ? entry : entry?.did;
      if (!isDid(sub)) { console.error(`no did for subject "${subject}" in ${o.agents || '(no --agents file)'}`); process.exit(1); }
      out.push(await principal.issueMandate({ ...spec, sub, ...(ttlSec ? { ttlSec } : {}) }));
    }
    console.log(JSON.stringify(out, null, 2));
    break;
  }
  default:
    usage();
}
