// Only a standalone prose line counts: examples must not suppress the real link.
// A line ACCEPTS also takes for the reference is left as it is, and none added.
function ensureReference(body, reference, accepts = () => false) {
  let fence = null;
  let comment = false;
  let found = false;
  for (const line of body.split(/\r?\n/)) {
    if (comment) {
      if (line.includes('-->')) comment = false;
      continue;
    }
    if (fence) {
      if (new RegExp(`^ {0,3}${fence[0]}{${fence.length},}\\s*$`).test(line)) fence = null;
      continue;
    }
    const opening = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (opening) {
      fence = opening[1];
      continue;
    }
    if (line.includes('<!--')) {
      comment = !line.slice(line.indexOf('<!--') + 4).includes('-->');
      continue;
    }
    if (line === reference || accepts(line)) found = true;
  }
  if (found) return body;
  // A truncated example must not swallow the generated line either.
  const close = fence ? `\n${fence}` : comment ? '\n-->' : '';
  return `${body}${close}\n\n${reference}`;
}

// An agent whose change does only part of its issue says so with a line of
// its own that starts `Refs #N` or `Part of #N`: merging must not close the
// issue with the rest of it left (#974), so no `Closes #N` is added. It can
// only withhold the closing line, never add one, and a cross-repository item
// is only referenced anyway.
function linkIssues(output, itemRepo, outputRepo, issue) {
  const same = itemRepo.toLowerCase() === outputRepo.toLowerCase();
  const reference = same ? `Closes #${issue}` : `Refs ${itemRepo}#${issue}`;
  const accepts = line => same && [`Refs #${issue}`, `Part of #${issue}`].some(marker =>
    line.startsWith(marker) && /^(?:\s|$)/.test(line.slice(marker.length)));
  for (const item of output.items) {
    if (item.type === 'create_pull_request') item.body = ensureReference(item.body ?? '', reference, accepts);
  }
  return output;
}

if (require.main === module) {
  const fs = require('node:fs');
  const path = require('node:path');
  const file = path.join(process.env.GH_AW_TMP, 'agent_output.json');
  const output = JSON.parse(fs.readFileSync(file, 'utf8'));
  linkIssues(output, process.env.ITEM_REPO, process.env.OUTPUT_REPO, process.env.ISSUE);
  fs.writeFileSync(file, JSON.stringify(output));
}

module.exports = { ensureReference, linkIssues };
