/** Reject proxy HTML and malformed responses without exposing raw server output. */
export async function readJson<T = any>(response: Response): Promise<T> {
  if (response.status === 401) window.dispatchEvent(new Event('workspace-auth-expired'));
  if (response.status >= 500) {
    throw new Error('The API is unavailable. Check backend logs and administrator configuration, then retry.');
  }
  if (!response.headers.get('content-type')?.includes('application/json')) {
    throw new Error('The API returned an unexpected response. Check that the frontend proxy points to the running backend.');
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error('The API returned invalid JSON. Check the backend logs and retry.'); }
  if (!response.ok) throw new Error(typeof data?.detail === 'string' ? data.detail : `Request failed (${response.status}). Check the submitted details.`);
  return data as T;
}
