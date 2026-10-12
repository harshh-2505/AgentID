// Builds the console as a static site in dist/. With no server behind it, the
// console runs the whole authority in the browser tab (see web/app/backend.js).
import { cp, rm, mkdir, readFile, writeFile } from 'node:fs/promises';

const out = new URL('../dist/', import.meta.url);
const from = (p) => new URL(`../${p}`, import.meta.url);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await cp(from('web'), out, { recursive: true });
await cp(from('core'), new URL('core', out), { recursive: true });
await mkdir(new URL('gateway', out), { recursive: true });
await cp(from('gateway/core.js'), new URL('gateway/core.js', out));
await mkdir(new URL('policy', out), { recursive: true });
await cp(from('policy/dsl.js'), new URL('policy/dsl.js', out));
// web/index.html is written as a page body (the server and the artifact host add
// the shell), so give the static copy its own document shell.
const index = new URL('index.html', out);
const body = await readFile(index, 'utf8');
if (!/^\s*<!doctype/i.test(body)) {
  await writeFile(index, '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>\n' + body + '</body></html>\n');
}
console.log('Static console written to dist/');
