import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { runReconJob } from './jobs/recon.ts'

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY!
)

const concurrency = parseInt(process.env.WORKER_CONCURRENCY ?? '2')
let running = 0
let shutdown = false

async function poll() {
  if (shutdown || running >= concurrency) return

  const slots = concurrency - running
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: scans } = await (supabase as any)
    .from('scans')
    .select('id, target, user_id')
    .eq('status', 'queued')
    .order('created_at', { ascending: true })
    .limit(slots)

  if (!scans || scans.length === 0) return

  for (const scan of scans) {
    // Claim the scan atomically — only process if still queued
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data: claimed } = await (supabase as any)
      .from('scans')
      .update({ status: 'running' })
      .eq('id', scan.id)
      .eq('status', 'queued')
      .select('id')
      .single()

    if (!claimed) continue

    running++
    console.log(`[worker] Starting scan ${scan.id} for target ${scan.target}`)

    runReconJob(scan.id, scan.target, scan.user_id)
      .then(() => console.log(`[worker] Scan ${scan.id} completed`))
      .catch((err: Error) => console.error(`[worker] Scan ${scan.id} failed:`, err.message))
      .finally(() => { running-- })
  }
}

const interval = setInterval(poll, 5000)
poll()

console.log('[worker] ReconX worker started — polling Supabase for queued scans...')

process.on('SIGTERM', async () => {
  console.log('[worker] Shutting down gracefully...')
  shutdown = true
  clearInterval(interval)
  // Wait up to 30s for running jobs
  let waited = 0
  while (running > 0 && waited < 30000) {
    await new Promise(r => setTimeout(r, 500))
    waited += 500
  }
  process.exit(0)
})
