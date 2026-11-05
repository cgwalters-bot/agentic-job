// The action's post step, which the runner registers when the main step
// starts and runs after the job's last step: a downloaded action's post
// step runs the same way, as the runner's user, after the lock.
import { spawnSync } from 'node:child_process';

const { status, error } = spawnSync('secure-host', ['probe', 'confined', 'post'], { stdio: 'inherit' });
if (error) throw error;
process.exitCode = status ?? 1;
