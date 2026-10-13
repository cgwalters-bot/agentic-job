// The action's main step: a third-party JavaScript action's stand-in
// (action.yml, whose post step is post.mjs).
import { probe } from './probe.mjs';

await probe('confined', 'action');
