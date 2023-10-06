export async function fetchWithTimeout(
  resource: RequestInfo,
  options: RequestInit & { timeout?: number } = {},
) {
  const { timeout = 8000 } = options;

  const response = await fetch(resource, {
    ...options,
    signal: AbortSignal.timeout(timeout),
  });
  return response;
}
