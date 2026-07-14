export const BROWSER_SESSION_HEADER = "BrokerKit-Session";
export const MAX_BROWSER_SESSION_BYTES = 4096;

export function validBrowserSession(value: string): boolean {
  return (
    value.length >= 32 &&
    value.length <= MAX_BROWSER_SESSION_BYTES &&
    /^[\x21-\x2B\x2D-\x7E]+$/u.test(value)
  );
}
