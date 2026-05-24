import { promises as dns } from 'dns'

export interface DnsRecord {
  type: string
  name: string
  value: string
  priority?: number
}

export async function enumerateDns(domain: string): Promise<DnsRecord[]> {
  const results: DnsRecord[] = []

  const run = async <T>(fn: () => Promise<T>, handler: (data: T) => void) => {
    try { handler(await fn()) } catch { /* record type not found */ }
  }

  await run(() => dns.resolve4(domain), records =>
    records.forEach(v => results.push({ type: 'A', name: domain, value: v })))

  await run(() => dns.resolve6(domain), records =>
    records.forEach(v => results.push({ type: 'AAAA', name: domain, value: v })))

  await run(() => dns.resolveMx(domain), records =>
    records.forEach(r => results.push({ type: 'MX', name: domain, value: r.exchange, priority: r.priority })))

  await run(() => dns.resolveNs(domain), records =>
    records.forEach(v => results.push({ type: 'NS', name: domain, value: v })))

  await run(() => dns.resolveTxt(domain), records =>
    records.forEach(r => results.push({ type: 'TXT', name: domain, value: r.join(' ') })))

  await run(() => dns.resolveCname(domain), records =>
    records.forEach(v => results.push({ type: 'CNAME', name: domain, value: v })))

  return results
}
