export interface WhoisInfo {
  registrar: string | null
  registered: string | null
  expires: string | null
  updated: string | null
  nameservers: string[]
  status: string[]
}

export async function fetchWhois(domain: string): Promise<WhoisInfo | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(15000),
    })
    if (!res.ok) return null
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await res.json()

    const events: Array<{ eventAction: string; eventDate: string }> = data.events ?? []
    const getEvent = (action: string) => events.find(e => e.eventAction === action)?.eventDate ?? null

    const nameservers: string[] = (data.nameservers ?? [])
      .map((ns: { ldhName?: string }) => ns.ldhName)
      .filter(Boolean)

    const status: string[] = Array.isArray(data.status) ? data.status : []

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const registrarEntity = (data.entities ?? []).find((e: any) => e.roles?.includes('registrar'))
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const fnEntry = registrarEntity?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')
    const registrar: string | null = fnEntry?.[3] ?? null

    return {
      registrar,
      registered: getEvent('registration'),
      expires: getEvent('expiration'),
      updated: getEvent('last changed'),
      nameservers,
      status,
    }
  } catch (err) {
    console.warn('[whois] error:', (err as Error).message)
    return null
  }
}
