import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)

export interface SubfinderResult {
  subdomain: string
  source?: string
}

export async function runSubfinder(target: string, timeout = 120): Promise<SubfinderResult[]> {
  try {
    const { stdout } = await execAsync(
      `subfinder -d ${target} -silent -timeout ${timeout} -json`,
      { timeout: (timeout + 10) * 1000, maxBuffer: 50 * 1024 * 1024 }
    )
    const results: SubfinderResult[] = []
    for (const line of stdout.split('\n').filter(Boolean)) {
      try {
        const parsed = JSON.parse(line)
        results.push({ subdomain: parsed.host, source: parsed.source })
      } catch {
        results.push({ subdomain: line.trim() })
      }
    }
    return results.filter(r => r.subdomain && r.subdomain.endsWith(target))
  } catch (err) {
    console.error('[subfinder] error:', err)
    return []
  }
}
