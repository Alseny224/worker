import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync } from 'node:fs'

const exec = promisify(execFile)

export interface GobusterResult {
  path: string
  status: number
  size?: number
}

const WORDLISTS = [
  '/usr/share/wordlists/dirb/common.txt',
  '/usr/share/dirb/wordlists/common.txt',
  '/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt',
]

export async function runGobuster(baseUrl: string): Promise<GobusterResult[]> {
  const wordlist = WORDLISTS.find(w => existsSync(w))
  if (!wordlist) throw new Error('No wordlist found — run: sudo apt install dirb')

  const { stdout } = await exec('gobuster', [
    'dir',
    '-u', baseUrl,
    '-w', wordlist,
    '-q',
    '--no-error',
    '-t', '20',
    '--timeout', '5s',
    '--status-codes', '200,204,301,302,307,401,403,500',
  ], { timeout: 120_000 })

  const results: GobusterResult[] = []
  for (const line of stdout.split('\n')) {
    // Format: /path   (Status: 200) [Size: 1234]
    const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/)
    if (m) results.push({ path: m[1], status: parseInt(m[2]), size: m[3] ? parseInt(m[3]) : undefined })
  }
  return results
}
