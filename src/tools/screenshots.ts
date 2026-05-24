import { chromium } from 'playwright'
import { createClient } from '@supabase/supabase-js'
import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'

export interface ScreenshotResult {
  url: string
  image_path: string
}

export async function captureScreenshots(urls: string[], scanId: string, limit = 50): Promise<ScreenshotResult[]> {
  const supabase = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_KEY!
  )
  const targets = urls.slice(0, limit)
  if (!targets.length) return []

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'reconx-'))
  const results: ScreenshotResult[] = []

  const executablePath = process.env.CHROMIUM_PATH || undefined
  const browser = await chromium.launch({ executablePath, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true })

  for (const url of targets) {
    const page = await context.newPage()
    try {
      await page.goto(url, { timeout: 12000, waitUntil: 'domcontentloaded' })
      const imgPath = path.join(tmpDir, `${Buffer.from(url).toString('base64').slice(0, 40)}.png`)
      await page.screenshot({ path: imgPath, fullPage: false })

      const imgData = await fs.readFile(imgPath)
      const storagePath = `screenshots/${scanId}/${path.basename(imgPath)}`
      const { error } = await supabase.storage.from('reconx').upload(storagePath, imgData, { contentType: 'image/png', upsert: true })

      if (!error) {
        const { data: { publicUrl } } = supabase.storage.from('reconx').getPublicUrl(storagePath)
        results.push({ url, image_path: publicUrl })
      }
    } catch {
      // skip failed screenshots
    } finally {
      await page.close()
    }
  }

  await browser.close()
  await fs.rm(tmpDir, { recursive: true, force: true })
  return results
}
