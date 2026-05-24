import { createClient } from '@supabase/supabase-js'
import { queryCrtsh } from '../tools/crtsh.ts'
import { enumerateDns } from '../tools/dns-enum.ts'
import { fetchWhois } from '../tools/whois.ts'
import { queryWayback } from '../tools/wayback.ts'
import { runTheHarvester } from '../tools/theharvester.ts'

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!)
}

async function updateScan(scanId: string, data: Record<string, unknown>) {
  await getSupabase().from('scans').update(data).eq('id', scanId)
}

function computeScore(subdomainCount: number, dnsCount: number, hasWhois: boolean, emailCount: number, waybackTotal: number): number {
  let score = 0
  if (subdomainCount > 0) score += Math.min(subdomainCount / 10, 3)
  if (dnsCount > 0)       score += Math.min(dnsCount / 5, 2)
  if (hasWhois)           score += 2
  if (emailCount > 0)     score += Math.min(emailCount / 5, 2)
  if (waybackTotal > 0)   score += Math.min(waybackTotal / 1000, 1)
  return Math.round(Math.min(score, 10) * 10) / 10
}

export async function runOsintJob(scanId: string, target: string) {
  console.log(`[osint] Starting scan ${scanId} for ${target}`)
  await updateScan(scanId, { status: 'running', step: 'Démarrage OSINT...' })

  try {
    // Step 1: crt.sh
    console.log(`[osint] Step 1: crt.sh`)
    await updateScan(scanId, { step: 'Recherche de subdomains via crt.sh...' })
    const crtResults = await queryCrtsh(target)
    console.log(`[osint] ${crtResults.length} subdomains via crt.sh`)

    // Step 2: DNS
    console.log(`[osint] Step 2: DNS`)
    await updateScan(scanId, { step: 'Énumération DNS (A, MX, NS, TXT, CNAME)...' })
    const dnsResults = await enumerateDns(target)
    console.log(`[osint] ${dnsResults.length} DNS records`)

    // Step 3: WHOIS
    console.log(`[osint] Step 3: WHOIS`)
    await updateScan(scanId, { step: 'Requête WHOIS / RDAP...' })
    const whoisInfo = await fetchWhois(target)

    // Step 4: Wayback Machine
    console.log(`[osint] Step 4: Wayback CDX`)
    await updateScan(scanId, { step: 'Analyse des URLs historiques (Wayback Machine)...' })
    const wayback = await queryWayback(target)
    console.log(`[osint] Wayback: ${wayback.total} URLs, ${wayback.interesting.length} intéressantes`)

    // Step 5: theHarvester (emails, hosts)
    console.log(`[osint] Step 5: theHarvester`)
    await updateScan(scanId, { step: 'Récolte d\'emails et hôtes (theHarvester)...' })
    const harvester = await runTheHarvester(target)
    console.log(`[osint] Harvester: ${harvester.emails.length} emails, ${harvester.hosts.length} hosts`)

    // Persist
    const db = getSupabase()

    // Merge subdomains from crt.sh and harvester (deduplicated)
    const allSubdomains = [...new Set([
      ...crtResults.map(r => r.subdomain),
      ...harvester.hosts,
    ])]

    if (allSubdomains.length > 0) {
      await db.from('subdomains').insert(
        allSubdomains.map(sub => ({
          scan_id: scanId,
          subdomain: sub,
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

    // Store wayback interesting URLs as endpoints
    if (wayback.interesting.length > 0) {
      await db.from('endpoints').insert(
        wayback.interesting.map(url => ({
          scan_id: scanId,
          url,
          status_code: null,
          source: 'wayback',
        }))
      )
    }

    const osintInfo = {
      emails: harvester.emails,
      wayback_total: wayback.total,
      wayback_interesting: wayback.interesting,
    }

    const score = computeScore(
      allSubdomains.length,
      dnsResults.length,
      !!whoisInfo,
      harvester.emails.length,
      wayback.total,
    )

    await updateScan(scanId, {
      status: 'done',
      completed_at: new Date().toISOString(),
      step: null,
      score,
      subdomain_count: allSubdomains.length,
      alive_count: 0,
      port_count: 0,
      whois_info: whoisInfo,
      osint_info: osintInfo,
    })

    console.log(`[osint] Scan ${scanId} complete — score ${score}/10`)
  } catch (err) {
    console.error(`[osint] Scan ${scanId} failed:`, err)
    await updateScan(scanId, { status: 'failed', completed_at: new Date().toISOString(), step: null })
    throw err
  }
}
