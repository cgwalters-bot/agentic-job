// The action's main step: a third-party JavaScript action's stand-in
// (action.yml, whose post step is post.mjs). The probe is the secure-host
// the image installed, run as this step's child with its environment.
import { spawnSync } from 'node:child_process';

const { status, error } = spawnSync('secure-host', ['probe', 'confined', 'main'], { stdio: 'inherit' });
if (error) throw error;
process.exitCode = status ?? 1;
