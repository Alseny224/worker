import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)

export interface HttpxResult {
  url: string
  host: string
  status_code: number
  title: string
  technologies: string[]
  cdn: string | null
  server: string | null
  alive: boolean
}

export async function runHttpx(hosts: string[], timeout = 180): Promise<HttpxResult[]> {
  if (!hosts.length) return []

  const input = hosts.join('\n')
  const cmd = `echo "${input.replace(/"/g, '\\"')}" | httpx -silent -status-code -title -tech-detect -cdn -server -json -timeout 10`

  try {
    const { stdout } = await execAsync(cmd, { timeout: (timeout + 10) * 1000, maxBuffer: 100 * 1024 * 1024 })
    const results: HttpxResult[] = []
    for (const line of stdout.split('\n').filter(Boolean)) {
      try {
        const p = JSON.parse(line)
        results.push({
          url: p.url ?? p.input,
          host: p.host ?? p.input,
          status_code: p.status_code ?? 0,
          title: p.title ?? '',
          technologies: p.tech ?? [],
          cdn: p.cdn_name ?? null,
          server: p.webserver ?? null,
          alive: !!p.status_code,
        })
      } catch {
        // skip malformed lines
      }
    }
    return results
  } catch (err) {
    console.error('[httpx] error:', err)
    return []
  }
}
