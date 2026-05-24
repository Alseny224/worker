import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync } from 'node:fs'

const exec = promisify(execFile)

export interface SslResult {
  host: string
  issues: string[]
  protocols: string[]
  ciphers: string[]
}

function resolveTestsslPath(): string | null {
  const candidates = [
    process.env.TESTSSL_PATH,
    `${process.env.HOME}/.local/bin/testssl.sh`,
    '/usr/local/bin/testssl.sh',
    '/usr/bin/testssl',
  ].filter(Boolean) as string[]

  return candidates.find(p => existsSync(p)) ?? null
}

export async function runTestssl(host: string): Promise<SslResult> {
  const bin = resolveTestsslPath()
  if (!bin) throw new Error('testssl.sh not found')

  const { stdout } = await exec('bash', [bin,
    '--quiet',
    '--color', '0',
    '--fast',
    '--protocols',
    '--vulnerable',
    host,
  ], { timeout: 120_000 })

  const issues: string[] = []
  const protocols: string[] = []
  const ciphers: string[] = []

  for (const line of stdout.split('\n')) {
    const clean = line.replace(/\x1b\[[0-9;]*m/g, '').trim()
    if (!clean) continue

    if (/VULNERABLE|CRITICAL|HIGH|WARN/i.test(clean) && clean.length > 10) {
      issues.push(clean)
    }
    const proto = clean.match(/\b(TLSv[\d.]+|SSLv[\d.]+)\b/)?.[1]
    if (proto && !protocols.includes(proto)) protocols.push(proto)

    if (/ECDHE|DHE|RC4|NULL|EXPORT|DES\b/i.test(clean)) {
      const cipher = clean.match(/\b([A-Z0-9_-]{8,})\b/)?.[1]
      if (cipher && !ciphers.includes(cipher)) ciphers.push(cipher)
    }
  }

  return { host, issues, protocols, ciphers }
}
