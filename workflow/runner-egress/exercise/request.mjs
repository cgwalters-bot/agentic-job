const url = new URL(`${process.env.GITHUB_API_URL}/repos/${process.env.GITHUB_REPOSITORY}`);
const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
await response.body?.cancel();
if (!response.ok) throw new Error(`Public metadata request failed: ${response.status}`);
