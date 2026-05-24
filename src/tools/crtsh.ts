export interface CrtshResult {
  subdomain: string
}

export async function queryCrtsh(domain: string): Promise<CrtshResult[]> {
  try {
    const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(30000),
    })
    if (!res.ok) return []
    const data: Array<{ name_value: string }> = await res.json()
    const seen = new Set<string>()
    for (const cert of data) {
      for (const name of cert.name_value.split('\n')) {
        const clean = name.trim().replace(/^\*\./, '').toLowerCase()
        if (clean && clean.endsWith(domain) && !clean.includes('*')) {
          seen.add(clean)
        }
      }
    }
    return [...seen].map(s => ({ subdomain: s }))
  } catch (err) {
    console.warn('[crtsh] error:', (err as Error).message)
    return []
  }
}
