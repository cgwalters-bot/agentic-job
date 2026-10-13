// The action's post step, which the runner registers when the main step
// starts and runs after the job's last step: a downloaded action's post
// step runs the same way, as the runner's user, after the lock.
import { probe } from './probe.mjs';

await probe('confined', 'post');
