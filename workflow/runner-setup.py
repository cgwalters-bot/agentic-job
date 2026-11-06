"""Admission and setup for the reusable workflow's same-user agent job."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


def main():
    mode = sys.argv[1]
    with open('.agentic-job/config.toml', 'rb') as source:
        config = tomllib.load(source)
    if mode == 'admit':
        with open('.agentic-job/policy.json') as source:
            policy = json.load(source)
        # The caller checkout is present even when the target is elsewhere.
        # Missing visibility is not evidence that either source is public.
        if os.environ.get('CALLER_PRIVATE') != 'false' or policy.get('private', False) is not False:
            sys.exit('the agent job refuses a private or unknown caller/target')
        # agentic-job.yml passes neither credential on, whichever user the
        # agent is, so `run` would have none: refused here, before setup.
        if config.get('inference', {}).get('register') == 'api-key' or config.get('mcp'):
            sys.exit('the agent job refuses inference-register api-key and [mcp.NAME]: their credentials are not passed on')
        agent_user = os.environ.get('AGENT_USER')
        if agent_user == 'sandbox':
            sys.exit('agent-user sandbox was removed with the sandbox user (agentic-job#2989): '
                     'drop the input, the runner is the only agent user')
        if agent_user != 'runner':
            sys.exit('agent-user must be runner')
        if config.get('session', {}).get('listen'):
            sys.exit('session.listen needs a second user, which there is none of since agentic-job#2989')
        return
    if mode != 'setup':
        sys.exit('expected admit or setup')
    script = config.get('setup', {}).get('script')
    if not script:
        return
    home = Path(os.environ['AGENT_HOME'])
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    installed = Path(os.environ['RUNNER_TEMP']) / 'agentic-job-setup-script'
    shutil.copyfile(script, installed)
    installed.chmod(0o700)
    env = {'HOME': str(home), 'LANG': 'C.UTF-8', 'PATH': '/usr/local/bin:/usr/bin:/bin'}
    # `agentic-job config` writes [host]; [sandbox] is its deprecated name
    # (agentic-job#2071), which the binary refuses beside it.
    env.update(config.get('host', config.get('sandbox', {})).get('env', {}))
    sys.exit(subprocess.run([str(installed)], cwd=home, env=env, check=False).returncode)


if __name__ == '__main__':
    main()
