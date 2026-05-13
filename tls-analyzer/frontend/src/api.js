const BASE = 'http://localhost:8000'

export async function analyzeText({ apkText, proxyText, nscXml }) {
  const form = new FormData()
  form.append('apk_text', apkText)
  form.append('proxy_text', proxyText)
  form.append('nsc_xml', nscXml)
  const res = await fetch(`${BASE}/analyze/text`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function analyzeAPK(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${BASE}/analyze/apk`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function analyzeHAR(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${BASE}/analyze/har`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function streamAI({ prompt, mode, onChunk, onDone }) {
  const res = await fetch(`${BASE}/ai/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, mode }),
  })
  if (!res.ok) throw new Error(await res.text())

  const reader = res.body.getReader()
  const dec = new TextDecoder()
  let buf = ''

  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      const lines = buf.split(/\r?\n/)
      buf = lines.pop() ?? ''
      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed.startsWith('data: ')) continue
        const data = trimmed.slice(6).trim()
        if (!data || data === '[DONE]') continue
        try {
          const json = JSON.parse(data)
          if (json.type === 'content_block_delta' && json.delta?.text) {
            onChunk(json.delta.text)
          }
        } catch {}
      }
    }
  } finally {
    onDone?.()
  }
}

export async function checkHealth() {
  try {
    const res = await fetch(`${BASE}/health`)
    return res.json()
  } catch {
    return { status: 'error' }
  }
}