export class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (init?.method && init.method !== "GET") {
    const csrf = window.sessionStorage.getItem("sentinel_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
    headers.set("Idempotency-Key", crypto.randomUUID());
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: "include", cache: "no-store" });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* safe fallback */ }
    throw new APIError(response.status, message);
  }
  return response.json() as Promise<T>;
}
