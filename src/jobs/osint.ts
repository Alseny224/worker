import { createClient } from '@supabase/supabase-js'
import { queryCrtsh } from '../tools/crtsh.ts'
import { enumerateDns } from '../tools/dns-enum.ts'
import { fetchWhois } from '../tools/whois.ts'

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!)
}

async function updateScan(scanId: string, data: Record<string, unknown>) {
  await getSupabase().from('scans').update(data).eq('id', scanId)
}

function computeScore(subdomainCount: number, dnsCount: number, hasWhois: boolean): number {
  let score = 0
  if (subdomainCount > 0) score += Math.min(subdomainCount / 10, 4)
  if (dnsCount > 0) score += Math.min(dnsCount / 5, 3)
  if (hasWhois) score += 3
  return Math.round(Math.min(score, 10) * 10) / 10
}

export async function runOsintJob(scanId: string, target: string) {
  console.log(`[osint] Starting scan ${scanId} for ${target}`)
  await updateScan(scanId, { status: 'running', step: 'Démarrage OSINT...' })

  try {
    // Step 1: crt.sh
    console.log(`[osint] Step 1: crt.sh → ${target}`)
    await updateScan(scanId, { step: 'Recherche de subdomains via crt.sh...' })
    const crtResults = await queryCrtsh(target)
    console.log(`[osint] ${crtResults.length} subdomains via crt.sh`)

    // Step 2: DNS
    console.log(`[osint] Step 2: DNS → ${target}`)
    await updateScan(scanId, { step: 'Énumération DNS (A, MX, NS, TXT, CNAME)...' })
    const dnsResults = await enumerateDns(target)
    console.log(`[osint] ${dnsResults.length} DNS records`)

    // Step 3: WHOIS
    console.log(`[osint] Step 3: WHOIS → ${target}`)
    await updateScan(scanId, { step: 'Requête WHOIS / RDAP...' })
    const whoisInfo = await fetchWhois(target)
    console.log(`[osint] WHOIS: ${whoisInfo ? 'found' : 'not found'}`)

    // Persist
    const db = getSupabase()

    if (crtResults.length > 0) {
      await db.from('subdomains').insert(
        crtResults.map(r => ({
          scan_id: scanId,
          subdomain: r.subdomain,
          alive: false,
          status_code: null,
          title: null,
          technologies: [],
          cdn: null,
          server: null,
        }))
      )
    }

    if (dnsResults.length > 0) {
      await db.from('dns_records').insert(
        dnsResults.map(r => ({
          scan_id: scanId,
          type: r.type,
          name: r.name,
          value: r.value,
          priority: r.priority ?? null,
        }))
      )
    }

    const score = computeScore(crtResults.length, dnsResults.length, !!whoisInfo)

    await updateScan(scanId, {
      status: 'done',
      completed_at: new Date().toISOString(),
      step: null,
      score,
      subdomain_count: crtResults.length,
      alive_count: 0,
      port_count: 0,
      whois_info: whoisInfo,
    })

    console.log(`[osint] Scan ${scanId} complete — score ${score}/10`)
  } catch (err) {
    console.error(`[osint] Scan ${scanId} failed:`, err)
    await updateScan(scanId, { status: 'failed', completed_at: new Date().toISOString(), step: null })
    throw err
  }
}
