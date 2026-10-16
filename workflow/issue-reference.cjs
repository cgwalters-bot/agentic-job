// Only a standalone prose line counts: examples must not suppress the real link.
function ensureReference(body, reference) {
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
    if (line === reference) found = true;
  }
  if (found) return body;
  // A truncated example must not swallow the generated line either.
  const close = fence ? `\n${fence}` : comment ? '\n-->' : '';
  return `${body}${close}\n\n${reference}`;
}

function linkIssues(output, itemRepo, outputRepo, issue) {
  const reference = itemRepo.toLowerCase() === outputRepo.toLowerCase()
    ? `Closes #${issue}` : `Refs ${itemRepo}#${issue}`;
  for (const item of output.items) {
    if (item.type === 'create_pull_request') item.body = ensureReference(item.body ?? '', reference);
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
