// The action's main step: a third-party JavaScript action's stand-in.
import { probe } from './probe.mjs';

await probe('confined', 'action');
