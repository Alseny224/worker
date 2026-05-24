import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync } from 'node:fs'

const exec = promisify(execFile)

export interface HarvesterResult {
  emails: string[]
  hosts: string[]
}

function resolveHarvesterPath(): string | null {
  const candidates = [
    process.env.THEHARVESTER_PATH,
    `${process.env.HOME}/.local/lib/theHarvester/theHarvester.py`,
    `${process.env.HOME}/.local/bin/theHarvester`,
    '/usr/bin/theHarvester',
    '/usr/local/bin/theHarvester',
  ].filter(Boolean) as string[]

  return candidates.find(p => existsSync(p)) ?? null
}

export async function runTheHarvester(domain: string): Promise<HarvesterResult> {
  const harvester = resolveHarvesterPath()
  if (!harvester) return { emails: [], hosts: [] }

  const bin = harvester.endsWith('.py') ? 'python3' : harvester
  const args = harvester.endsWith('.py')
    ? [harvester, '-d', domain, '-b', 'dnsdumpster,hackertarget,certspotter', '-l', '200']
    : ['-d', domain, '-b', 'dnsdumpster,hackertarget,certspotter', '-l', '200']

  try {
    const { stdout } = await exec(bin, args, { timeout: 90_000 })

    const emails: string[] = []
    const hosts: string[] = []
    let inEmails = false
    let inHosts = false

    for (const raw of stdout.split('\n')) {
      const line = raw.trim()
      if (!line) continue

      if (line.toLowerCase().includes('emails found')) { inEmails = true; inHosts = false; continue }
      if (line.toLowerCase().includes('hosts found') || line.toLowerCase().includes('ips found')) { inHosts = true; inEmails = false; continue }
      if (line.startsWith('[*]') || line.startsWith('---')) { inEmails = false; inHosts = false; continue }

      if (inEmails && /^[\w.+%-]+@[\w.-]+\.\w{2,}$/.test(line)) emails.push(line)
      if (inHosts && line.includes('.')) hosts.push(line.split(':')[0].trim())
    }

    return {
      emails: [...new Set(emails)],
      hosts: [...new Set(hosts)].filter(h => h.endsWith(domain)),
    }
  } catch {
    return { emails: [], hosts: [] }
  }
}
