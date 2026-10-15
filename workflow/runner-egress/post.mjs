import { appendFileSync, readFileSync, statSync } from 'node:fs';
import { destinations } from './parse.mjs';

const trace = process.env.STATE_trace;
if (!trace) throw new Error('Missing outbound trace state');
if (statSync(trace).size > 4 * 1024 * 1024) throw new Error('Outbound trace exceeds 4 MiB');
const list = destinations(readFileSync(trace, 'utf8'));
if (!list.length) throw new Error('No outbound destinations observed');
const report = `## Observed outbound IP destinations\n\n` +
  `Metadata only, not an allowlist. Up to 10,000 packets / 480 seconds; ` +
  `starts after checkout. Includes host background traffic.\n\n` +
  `Coverage ends at this final JavaScript post snapshot. Runner completion ` +
  `traffic after the last step is not observed. Limits may truncate coverage.\n\n` +
  `\`\`\`text\n${list.join('\n')}\n\`\`\`\n`;
console.log(report);
appendFileSync(process.env.GITHUB_STEP_SUMMARY, report);
