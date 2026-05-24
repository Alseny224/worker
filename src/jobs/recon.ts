import { createClient } from '@supabase/supabase-js'
import { runSubfinder } from '../tools/subfinder.ts'
import { runHttpx } from '../tools/httpx.ts'
import { runNaabu } from '../tools/naabu.ts'
import { captureScreenshots } from '../tools/screenshots.ts'
import { runGobuster } from '../tools/gobuster.ts'
import { runTestssl } from '../tools/testssl.ts'

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!)
}

async function updateScan(scanId: string, data: Record<string, unknown>) {
  await getSupabase().from('scans').update(data).eq('id', scanId)
}

function computeScore(subdomainCount: number, aliveCount: number, portCount: number, sslIssues: number): number {
  let score = 0
  if (subdomainCount > 0) score += Math.min(subdomainCount / 20, 3)
  if (aliveCount > 0)     score += Math.min(aliveCount / 10, 3)
  if (portCount > 0)      score += Math.min(portCount / 10, 3)
  if (sslIssues > 0)      score += Math.min(sslIssues / 3, 1)
  return Math.round(Math.min(score, 10) * 10) / 10
}

export async function runReconJob(scanId: string, target: string, userId: string) {
  console.log(`[recon] Starting scan ${scanId} for ${target}`)
  await updateScan(scanId, { status: 'running', step: 'Démarrage...' })

  try {
    // Step 1: Subdomain enumeration
    console.log(`[recon] Step 1: subfinder`)
    await updateScan(scanId, { step: 'Énumération des subdomains (subfinder)...' })
    const subfinderResults = await runSubfinder(target)
    const subdomains = [...new Set([target, ...subfinderResults.map(r => r.subdomain)])]
    console.log(`[recon] ${subdomains.length} subdomains`)

    // Step 2: HTTP probing
    console.log(`[recon] Step 2: httpx`)
    await updateScan(scanId, { step: `Sondage HTTP sur ${subdomains.length} hôtes (httpx)...` })
    const httpxResults = await runHttpx(subdomains)
    const aliveHosts = httpxResults.filter(r => r.alive)
    console.log(`[recon] ${aliveHosts.length} alive hosts`)

    // Step 3: Port scanning
    console.log(`[recon] Step 3: naabu`)
    await updateScan(scanId, { step: `Scan de ports sur ${aliveHosts.length} hôtes actifs (naabu)...` })
    const uniqueHosts = [...new Set(aliveHosts.map(h => h.host))]
    const portResults = await runNaabu(uniqueHosts)
    console.log(`[recon] ${portResults.length} open ports`)

    // Step 4: Screenshots (optional)
    console.log(`[recon] Step 4: screenshots`)
    await updateScan(scanId, { step: `Capture de screenshots...` })
    const aliveUrls = aliveHosts.map(h => h.url)
    let screenshotResults: import('../tools/screenshots.ts').ScreenshotResult[] = []
    try {
      screenshotResults = await captureScreenshots(aliveUrls, scanId)
      console.log(`[recon] ${screenshotResults.length} screenshots`)
    } catch (err) {
      console.warn(`[recon] Screenshots skipped:`, (err as Error).message.split('\n')[0])
    }

    // Step 5: Directory bruteforce (gobuster) — top 3 HTTPS hosts only
    const httpsHosts = aliveHosts.filter(h => h.url?.startsWith('https')).slice(0, 3)
    const allEndpoints: { url: string; status_code: number; source: string }[] = []
    if (httpsHosts.length > 0) {
      console.log(`[recon] Step 5: gobuster on ${httpsHosts.length} HTTPS hosts`)
      await updateScan(scanId, { step: `Découverte de répertoires cachés (gobuster)...` })
      for (const host of httpsHosts) {
        try {
          const dirs = await runGobuster(host.url)
          for (const d of dirs) {
            allEndpoints.push({ url: host.url + d.path, status_code: d.status, source: 'gobuster' })
          }
          console.log(`[recon] gobuster: ${dirs.length} paths on ${host.host}`)
        } catch (err) {
          console.warn(`[recon] gobuster skipped for ${host.host}:`, (err as Error).message.split('\n')[0])
        }
      }
    }

    // Step 6: SSL/TLS analysis (testssl.sh) — top 3 HTTPS hosts
    const sslResults: import('../tools/testssl.ts').SslResult[] = []
    if (httpsHosts.length > 0) {
      console.log(`[recon] Step 6: testssl on ${httpsHosts.length} hosts`)
      await updateScan(scanId, { step: `Analyse SSL/TLS (testssl.sh)...` })
      for (const host of httpsHosts) {
        try {
          const ssl = await runTestssl(host.host)
          sslResults.push(ssl)
          console.log(`[recon] testssl: ${ssl.issues.length} issues on ${host.host}`)
        } catch (err) {
          console.warn(`[recon] testssl skipped for ${host.host}:`, (err as Error).message.split('\n')[0])
        }
      }
    }

    // Persist
    const score = computeScore(
      subdomains.length,
      aliveHosts.length,
      portResults.length,
      sslResults.reduce((acc, r) => acc + r.issues.length, 0),
    )

    const db = getSupabase()

    if (httpxResults.length > 0) {
      await db.from('subdomains').insert(httpxResults.map(h => ({
        scan_id: scanId,
        subdomain: h.host,
        alive: h.alive,
        status_code: h.status_code || null,
        title: h.title || null,
        technologies: h.technologies,
        cdn: h.cdn,
        server: h.server,
      })))
    }

    if (portResults.length > 0) {
      await db.from('ports').insert(portResults.map(p => ({
        scan_id: scanId,
        host: p.host,
        port: p.port,
        service: p.service,
        protocol: p.protocol,
      })))
    }

    if (screenshotResults.length > 0) {
      await db.from('screenshots').insert(screenshotResults.map(s => ({
        scan_id: scanId,
        url: s.url,
        image_path: s.image_path,
      })))
    }

    if (allEndpoints.length > 0) {
      await db.from('endpoints').insert(allEndpoints.map(e => ({
        scan_id: scanId,
        url: e.url,
        status_code: e.status_code,
        source: e.source,
      })))
    }

    await updateScan(scanId, {
      status: 'done',
      completed_at: new Date().toISOString(),
      step: null,
      score,
      subdomain_count: subdomains.length,
      alive_count: aliveHosts.length,
      port_count: portResults.length,
      ssl_info: sslResults.length > 0 ? sslResults : null,
    })

    console.log(`[recon] Scan ${scanId} complete — score ${score}/10`)
  } catch (err) {
    console.error(`[recon] Scan ${scanId} failed:`, err)
    await updateScan(scanId, { status: 'failed', completed_at: new Date().toISOString(), step: null })
    throw err
  }
}
