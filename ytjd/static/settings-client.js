
async function applySettings() {
  try {
    const res = await fetch('/api/settings')
    if (!res.ok) return
    const s = await res.json()
    if (s.bg_url) document.body.style.backgroundImage = `url('${s.bg_url}')`
    if (s.theme) document.documentElement.setAttribute('data-theme', s.theme)
    if (s.particles_enabled) document.documentElement.setAttribute('data-particles', '1')
  } catch {}
}
document.addEventListener('DOMContentLoaded', applySettings)
