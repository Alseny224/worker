import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)

export interface PortResult {
  host: string
  port: number
  protocol: string
  service: string | null
}

const TOP_PORTS = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888'

export async function runNaabu(hosts: string[], timeout = 240): Promise<PortResult[]> {
  if (!hosts.length) return []

  const input = hosts.join('\n')
  const cmd = `echo "${input.replace(/"/g, '\\"')}" | naabu -p ${TOP_PORTS} -silent -json -timeout 5`

  try {
    const { stdout } = await execAsync(cmd, { timeout: (timeout + 10) * 1000, maxBuffer: 50 * 1024 * 1024 })
    const results: PortResult[] = []
    for (const line of stdout.split('\n').filter(Boolean)) {
      try {
        const p = JSON.parse(line)
        results.push({
          host: p.ip ?? p.host,
          port: p.port,
          protocol: p.protocol ?? 'tcp',
          service: null,
        })
      } catch {
        // skip malformed
      }
    }
    return results
  } catch (err) {
    console.error('[naabu] error:', err)
    return []
  }
}
