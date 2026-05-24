import { createClient } from '@supabase/supabase-js'
import { runSubfinder } from '../tools/subfinder.ts'
import { runHttpx } from '../tools/httpx.ts'
import { runNaabu } from '../tools/naabu.ts'
import { captureScreenshots } from '../tools/screenshots.ts'

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!)
}

async function updateScan(scanId: string, data: Record<string, unknown>) {
  await getSupabase().from('scans').update(data).eq('id', scanId)
}

function computeScore(subdomainCount: number, aliveCount: number, portCount: number): number {
  let score = 0
  if (subdomainCount > 0) score += Math.min(subdomainCount / 20, 3)
  if (aliveCount > 0) score += Math.min(aliveCount / 10, 3)
  if (portCount > 0) score += Math.min(portCount / 10, 4)
  return Math.round(Math.min(score, 10) * 10) / 10
}

export async function runReconJob(scanId: string, target: string, userId: string) {
  console.log(`[recon] Starting scan ${scanId} for ${target}`)

  await updateScan(scanId, { status: 'running', step: 'Démarrage...' })

  try {
    // Step 1: Subdomain enumeration
    console.log(`[recon] Step 1: subfinder → ${target}`)
    await updateScan(scanId, { step: 'Énumération des subdomains (subfinder)...' })
    const subfinderResults = await runSubfinder(target)
    const subdomains = [...new Set([target, ...subfinderResults.map(r => r.subdomain)])]
    console.log(`[recon] Found ${subdomains.length} subdomains`)

    // Step 2: HTTP probing
    console.log(`[recon] Step 2: httpx → ${subdomains.length} hosts`)
    await updateScan(scanId, { step: `Sondage HTTP sur ${subdomains.length} hôtes (httpx)...` })
    const httpxResults = await runHttpx(subdomains)
    const aliveHosts = httpxResults.filter(r => r.alive)
    console.log(`[recon] ${aliveHosts.length} alive hosts`)

    // Step 3: Port scanning
    console.log(`[recon] Step 3: naabu → ${aliveHosts.length} hosts`)
    await updateScan(scanId, { step: `Scan de ports sur ${aliveHosts.length} hôtes actifs (naabu)...` })
    const uniqueHosts = [...new Set(aliveHosts.map(h => h.host))]
    const portResults = await runNaabu(uniqueHosts)
    console.log(`[recon] Found ${portResults.length} open ports`)

    // Step 4: Screenshots (optional — skip if Playwright unavailable)
    console.log(`[recon] Step 4: screenshots → ${aliveHosts.length} URLs`)
    await updateScan(scanId, { step: `Capture de screenshots (${Math.min(aliveHosts.length, 50)} URLs)...` })
    const aliveUrls = aliveHosts.map(h => h.url)
    let screenshotResults: import('../tools/screenshots.ts').ScreenshotResult[] = []
    try {
      screenshotResults = await captureScreenshots(aliveUrls, scanId)
      console.log(`[recon] ${screenshotResults.length} screenshots captured`)
    } catch (err) {
      console.warn(`[recon] Screenshots skipped:`, (err as Error).message.split('\n')[0])
    }

    // Step 5: Persist to DB
    const score = computeScore(subdomains.length, aliveHosts.length, portResults.length)

    const subdomainRows = httpxResults.map(h => ({
      scan_id: scanId,
      subdomain: h.host,
      alive: h.alive,
      status_code: h.status_code || null,
      title: h.title || null,
      technologies: h.technologies,
      cdn: h.cdn,
      server: h.server,
    }))

    const portRows = portResults.map(p => ({
      scan_id: scanId,
      host: p.host,
      port: p.port,
      service: p.service,
      protocol: p.protocol,
    }))

    const screenshotRows = screenshotResults.map(s => ({
      scan_id: scanId,
      url: s.url,
      image_path: s.image_path,
    }))

    const db = getSupabase()
    if (subdomainRows.length > 0) {
      await db.from('subdomains').insert(subdomainRows)
    }
    if (portRows.length > 0) {
      await db.from('ports').insert(portRows)
    }
    if (screenshotRows.length > 0) {
      await db.from('screenshots').insert(screenshotRows)
    }

    await updateScan(scanId, {
      status: 'done',
      completed_at: new Date().toISOString(),
      score,
      subdomain_count: subdomains.length,
      alive_count: aliveHosts.length,
      port_count: portResults.length,
    })

    console.log(`[recon] Scan ${scanId} complete — score ${score}/10`)
  } catch (err) {
    console.error(`[recon] Scan ${scanId} failed:`, err)
    await updateScan(scanId, { status: 'failed', completed_at: new Date().toISOString() })
    throw err
  }
}
