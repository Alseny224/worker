export interface WaybackResult {
  total: number
  interesting: string[]
}

const INTERESTING = [
  '.git', '.env', '.bak', '.sql', '.zip', '.tar.gz',
  'backup', 'config', 'password', 'secret', 'token', 'private',
  '/admin', '/api/', '/wp-admin', '/phpmyadmin', '/adminer',
  '/.well-known', '/debug', '/console', '/actuator', '/swagger',
]

export async function queryWayback(domain: string): Promise<WaybackResult> {
  const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey&limit=5000&matchType=domain`
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    if (!res.ok) return { total: 0, interesting: [] }

    const data = await res.json() as string[][]
    const urls = data.slice(1).map(row => row[0])

    const interesting = urls
      .filter(u => INTERESTING.some(p => u.toLowerCase().includes(p)))
      .slice(0, 50)

    return { total: urls.length, interesting }
  } catch {
    return { total: 0, interesting: [] }
  }
}
