/* static/session-nav.js */
(() => {
  if (window.__SN_TRAY_INIT__) return;
  window.__SN_TRAY_INIT__ = true;

  const doc = document;
  const $ = (s, el = doc) => el.querySelector(s);
  const PATH = location.pathname.replace(/\/+$/, "");
  const ON_AUTH_PAGE = ["/li", "/si", "/signup"].includes(PATH);

  // Remixicon
  if (!doc.querySelector('link[href*="remixicon"]')) {
    const link = doc.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css";
    doc.head.appendChild(link);
  }

  // Styles (unchanged look)
  const addCSS = (css) => { const t = doc.createElement("style"); t.textContent = css; doc.head.appendChild(t); };
  addCSS(`
    :root{--sn-z:9999;--sn-dd-w:400px;--sn-panel:rgba(15,16,20,.88);--sn-stroke:rgba(255,255,255,.08);--sn-hover:rgba(255,255,255,.12);--sn-text:#e9edf5;--sn-muted:#a8b0c0;}
    .sn-tray{position:fixed;top:12px;right:12px;display:flex;gap:12px;align-items:center;white-space:nowrap;z-index:var(--sn-z);}
    .sn-icon-btn{width:36px;height:36px;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;background:#181c25;color:#fff;border:1px solid var(--sn-stroke);box-shadow:0 6px 18px rgba(0,0,0,.35);cursor:pointer;transition:background .15s,border-color .15s,transform .08s;}
    .sn-icon-btn:hover{background:#1d2330;border-color:var(--sn-hover)}.sn-icon-btn:active{transform:scale(.97)}
    .sn-icon-btn i{font-size:18px;opacity:.95}
    .sn-badge{position:absolute;top:-4px;right:-4px;min-width:16px;height:16px;padding:0 4px;background:#ff3b30;color:#fff;font-weight:700;font-size:10px;border-radius:999px;display:none;align-items:center;justify-content:center;border:2px solid #0c0e13}
    .sn-dd{position:fixed;width:var(--sn-dd-w);max-height:64vh;overflow:auto;background:var(--sn-panel);color:var(--sn-text);border:1px solid var(--sn-stroke);border-radius:16px;padding:10px;z-index:var(--sn-z);box-shadow:0 24px 70px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.02) inset;backdrop-filter:blur(10px)}
    .sn-dd[hidden]{display:none}.sn-dd .sn-dd-hdr{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 8px 10px;border-bottom:1px dashed var(--sn-stroke);margin-bottom:8px}
    .sn-title{font-weight:800;font-size:13px;letter-spacing:.35px;opacity:.95}
    .sn-markall{font-size:12px;line-height:24px;padding:0 12px;border-radius:10px;border:1px solid var(--sn-stroke);background:#121722;color:var(--sn-text);cursor:pointer}
    .sn-markall:hover{background:#161c2a;border-color:var(--sn-hover)}
    .sn-list{display:flex;flex-direction:column;gap:10px;padding:6px}
    .sn-empty{padding:18px;text-align:center;color:var(--sn-muted);font-size:13px}
    .sn-item{position:relative;display:flex;gap:12px;align-items:flex-start;background:#12161f;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:12px 40px 12px 12px;cursor:pointer;transition:border-color .15s,background .15s}
    .sn-item:hover{border-color:var(--sn-hover);background:#151b28}.sn-item.read{opacity:.9}
    .sn-dot{width:8px;height:8px;border-radius:50%;background:#ff3b30;margin-top:6px;flex:0 0 8px}.sn-item.read .sn-dot{background:#2b2f3c}
    .sn-text{flex:1;min-width:0}.sn-t{font-weight:800;font-size:13px;margin-bottom:3px;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .sn-b{font-size:12px;color:#cfd6e4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:flex;align-items:center;gap:8px}
    .sn-more{font-size:11px;padding:4px 8px;border-radius:8px;cursor:pointer;border:1px solid rgba(255,255,255,.14);background:#192133;color:#eaeaea}
    .sn-more:hover{background:#1e2840}
    .sn-meta{margin-top:6px;font-size:11px;color:#9aa6bd}
    .sn-trash{position:absolute;right:10px;top:10px;width:28px;height:28px;border-radius:9px;display:flex;align-items:center;justify-content:center;background:#2a0000;border:1px solid rgba(255,0,0,.22);color:#ff8080;cursor:pointer;opacity:0;transform:scale(.92);transition:opacity .12s,transform .12s,background .12s,color .12s}
    .sn-item:hover .sn-trash{opacity:1;transform:scale(1)}.sn-trash:hover{background:#3b0000;color:#ff9a9a}
    .sn-profile-head{display:flex;align-items:center;gap:12px;padding:10px 10px 12px;border-bottom:1px dashed var(--sn-stroke);margin-bottom:8px}
    .sn-avatar{width:40px;height:40px;border-radius:12px;background:linear-gradient(180deg,#1e2536,#131926);display:flex;align-items:center;justify-content:center;border:1px solid var(--sn-stroke);color:#fff}
    .sn-avatar i{font-size:18px;opacity:.95}.sn-u{display:flex;flex-direction:column}.sn-name{font-weight:900;font-size:13px;color:#fff;letter-spacing:.2px}.sn-role{font-size:11px;color:var(--sn-muted)}
    .sn-menu{display:flex;flex-direction:column;gap:8px;padding:6px}
    .sn-link{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;border:1px solid var(--sn-stroke);background:#121722;color:var(--sn-text);text-decoration:none;cursor:pointer;transition:background .15s,border-color .15s,transform .08s;font-size:13px}
    .sn-link i{font-size:18px;color:#9db2ff}.sn-link:hover{background:#151c2a;border-color:var(--sn-hover)}.sn-link:active{transform:scale(.98)}
    .sn-op{background:linear-gradient(180deg,rgba(122,162,255,.15),rgba(122,162,255,.02));border-color:#3a4761}
    .sn-op i{color:#bcd0ff}.sn-logout{background:linear-gradient(180deg,rgba(255,80,80,.12),rgba(255,80,80,.02));border-color:rgba(255,80,80,.25)}.sn-logout i{color:#ff9a9a}
    .sn-modal-backdrop{position:fixed;inset:0;display:none;place-items:center;z-index:var(--sn-z);background:rgba(0,0,0,.6)}
    .sn-modal{width:min(720px,92vw);background:var(--sn-panel);border:1px solid var(--sn-stroke);border-radius:16px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
    .sn-modal-hdr{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;border-bottom:1px dashed var(--sn-stroke)}
    .sn-modal-title{font-weight:900;font-size:14px;color:#fff}
    .sn-modal-close{width:32px;height:32px;border-radius:10px;border:1px solid var(--sn-stroke);background:#141a26;color:#eaeaea;display:grid;place-items:center;cursor:pointer}
    .sn-modal-close:hover{background:#192133}.sn-modal-body{padding:14px;font-size:13px;color:#eaeaea;white-space:pre-wrap}
  `);

  // Tray + dropdown DOM
  const tray = doc.createElement("div");
  tray.className = "sn-tray";
  tray.innerHTML = `
    <button class="sn-icon-btn" id="snBellBtn" aria-label="Notifications" style="position:relative">
      <i class="ri-notification-3-line"></i>
      <span class="sn-badge" id="snBadge">!</span>
    </button>
    <button class="sn-icon-btn" id="snProfileBtn" aria-label="Profile" style="position:relative">
      <i class="ri-user-3-line"></i>
    </button>`;
  doc.body.appendChild(tray);

  const tpl = doc.createElement("template");
  tpl.innerHTML = `
    <div class="sn-dd" id="snBellDD" hidden>
      <div class="sn-dd-hdr">
        <div class="sn-title">Notifications</div>
        <button class="sn-markall" id="snMarkAll">Mark all read</button>
      </div>
      <div class="sn-list" id="snList"><div class="sn-empty">You're all caught up ✨</div></div>
    </div>
    <div class="sn-dd" id="snProfileDD" hidden style="width:320px;">
      <div class="sn-profile-head">
        <div class="sn-avatar"><i class="ri-user-3-line"></i></div>
        <div class="sn-u">
          <div class="sn-name" id="snProfName">Guest</div>
          <div class="sn-role" id="snProfRole">user</div>
        </div>
      </div>
      <div class="sn-menu" id="snMenu">
        <a class="sn-link" href="/st"><i class="ri-settings-3-line"></i><span>Settings</span></a>
        <a class="sn-link sn-op" href="/op" id="snOpLink" hidden><i class="ri-shield-star-line"></i><span>Owner Panel</span></a>
        <button class="sn-link sn-logout" id="snLogoutBtn" type="button"><i class="ri-logout-circle-r-line"></i><span>Logout</span></button>
      </div>
    </div>
    <div class="sn-modal-backdrop" id="snModal" role="dialog" aria-modal="true" aria-labelledby="snModalTitle">
      <div class="sn-modal">
        <div class="sn-modal-hdr">
          <div class="sn-modal-title" id="snModalTitle"></div>
          <button class="sn-modal-close" id="snModalClose" aria-label="Close"><i class="ri-close-line"></i></button>
        </div>
        <div class="sn-modal-body" id="snModalBody"></div>
      </div>
    </div>
  `.trim();
  for (const n of tpl.content.childNodes) doc.body.appendChild(n);

  // Refs
  const bellBtn = tray.querySelector("#snBellBtn");
  const profBtn = tray.querySelector("#snProfileBtn");
  const bellDD = $("#snBellDD");
  const profDD = $("#snProfileDD");
  const badge = tray.querySelector("#snBadge");
  const listEl = $("#snList");
  const markAllBtn = $("#snMarkAll");
  const profName = $("#snProfName");
  const profRole = $("#snProfRole");
  const opLink = $("#snOpLink");
  const logoutBtn = $("#snLogoutBtn");
  const menuEl = $("#snMenu");

  const modal = $("#snModal");
  const modalTitle = $("#snModalTitle");
  const modalBody = $("#snModalBody");
  const modalClose = $("#snModalClose");

  let notifications = [];
  let isAuthed = false;
  let role = "user";

  // Position near navbar (or top-right fallback)
  function getNavbar() { const el = doc.querySelector(".fixed-nav-bar"); if (!el) return null; const r = el.getBoundingClientRect(); return (r.width>0 && r.height>0) ? el : null; }
  function placeTray() {
    if (ON_AUTH_PAGE) { tray.style.display="none"; bellDD.hidden = profDD.hidden = true; return; }
    tray.style.display="flex";
    const nb = getNavbar();
    if (nb) {
      const r = nb.getBoundingClientRect();
      const top = Math.max(0, Math.round(r.top + (r.height - 36)/2) - 25);
      tray.style.top = `${top}px`;
      tray.style.right = `${Math.max(0, window.innerWidth - r.right + 12)}px`;
    } else { tray.style.top="12px"; tray.style.right="12px"; }
  }
  placeTray();
  addEventListener("resize", placeTray, { passive:true });
  addEventListener("scroll", placeTray, { passive:true });
  new MutationObserver(placeTray).observe(doc.documentElement, { childList:true, subtree:true });

  // Helpers
  const getJSON = async (url) => {
    try {
      const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) throw 0; const ct = r.headers.get("content-type")||"";
      return ct.includes("application/json") ? r.json() : null;
    } catch { return null; }
  };
  const postJSON = (url, body={}) =>
    fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"same-origin", body:JSON.stringify(body) });

  // Badge + list
  function updateBadge(){
    if (!isAuthed) { badge.textContent="!"; badge.style.display="inline-flex"; return; }
    const unread = notifications.filter(n=>!n.read).length;
    if (unread>0){ badge.textContent = unread>99 ? "99+" : String(unread); badge.style.display="inline-flex"; }
    else badge.style.display="none";
  }

  const MAX_PREVIEW = 140;
  const esc = (s)=>String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");

  function renderList(){
    listEl.innerHTML = "";
    if (!notifications.length){ listEl.innerHTML = `<div class="sn-empty">You're all caught up ✨</div>`; updateBadge(); return; }
    for (const n of notifications){
      const item = doc.createElement("div");
      item.className = `sn-item${n.read?" read":""}`;
      item.setAttribute("role","button"); item.tabIndex = 0;
      const body = n.body||""; const needsMore = body.length>MAX_PREVIEW; const preview = needsMore ? body.slice(0,MAX_PREVIEW-1)+"…" : body;
      item.innerHTML = `
        <div class="sn-dot"></div>
        <div class="sn-text">
          <div class="sn-t" title="${esc(n.title)}">${esc(n.title)}</div>
          <div class="sn-b"><span class="sn-preview">${esc(preview)}</span>${needsMore?`<button class="sn-more" type="button">Read more</button>`:""}</div>
          <div class="sn-meta">${esc(new Date(n.created_at).toLocaleString())}</div>
        </div>
        <button class="sn-trash" title="Delete"><i class="ri-delete-bin-6-line"></i></button>`;
      item.querySelector(".sn-trash").addEventListener("click", async (e)=>{ e.stopPropagation(); try{await postJSON("/api/notifications/delete",{id:n.id});}catch{} notifications = notifications.filter(x=>x.id!==n.id); item.remove(); if(!notifications.length) renderList(); else updateBadge(); });
      item.querySelector(".sn-more")?.addEventListener("click", async (e)=>{ e.stopPropagation(); openModal(n.title, n.body); if(!n.read){ try{await postJSON("/api/notifications/read",{id:n.id});}catch{} n.read=true; item.classList.add("read"); updateBadge(); } });
      item.addEventListener("click", async()=>{ if(!n.read){ try{await postJSON("/api/notifications/read",{id:n.id});}catch{} n.read=true; item.classList.add("read"); updateBadge(); } });
      item.addEventListener("keydown", async(e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); if(!n.read){ try{await postJSON("/api/notifications/read",{id:n.id});}catch{} n.read=true; item.classList.add("read"); updateBadge(); } } });
      listEl.appendChild(item);
    }
    updateBadge();
  }
  async function loadNotifications(){ if(!isAuthed) return; const data = await getJSON("/api/notifications"); notifications = (data && data.items)||[]; renderList(); }

  // *** Only hide links explicitly marked as auth links ***
  function toggleAuthLinks(authed) {
    const authNodes = doc.querySelectorAll('[data-auth-link="true"]');
    authNodes.forEach(el => {
      el.style.display = authed ? "none" : "";
      el.setAttribute("aria-hidden", authed ? "true" : "false");
      if (authed) el.setAttribute("tabindex","-1"); else el.removeAttribute("tabindex");
    });
  }

  // Session
  function renderLoggedOutMenu(){
    if (menuEl) {
      menuEl.innerHTML = `
        <a class="sn-link" href="/li"><i class="ri-login-circle-line"></i><span>Login</span></a>
        <a class="sn-link" href="/signup"><i class="ri-user-add-line"></i><span>Sign up</span></a>
        <a class="sn-link" href="/st"><i class="ri-settings-3-line"></i><span>Settings</span></a>`;
    }
    notifications = [];
    badge.textContent = "!";
    badge.style.display = "inline-flex";
    toggleAuthLinks(false);
  }

  async function loadSession(){
    if (ON_AUTH_PAGE) { renderLoggedOutMenu(); placeTray(); return; }
    const res = await getJSON("/api/session");
    isAuthed = !!(res && res.authenticated);
    role = (res && res.role) || "user";
    if (isAuthed){
      profName.textContent = res.username || "User";
      profRole.textContent = role;
      if (role === "owner") opLink.hidden = false; else opLink.hidden = true;
      toggleAuthLinks(true);
      await loadNotifications();
    } else {
      renderLoggedOutMenu();
      opLink.hidden = true;
    }
    updateBadge();
    placeTray();
  }

  // Modal
  function openModal(t,b){ modalTitle.textContent=t||""; modalBody.textContent=b||""; modal.style.display="grid"; }
  function closeAll(){ bellDD.hidden = true; profDD.hidden = true; }
  function positionDropdown(panel, anchor){ const r = anchor.getBoundingClientRect(); const gap=8; panel.style.top = `${Math.round(r.bottom+gap)}px`; panel.style.right = `${Math.max(14, Math.round(window.innerWidth-r.right))}px`; }
  modal.addEventListener("click",(e)=>{ if(e.target===modal) modal.style.display="none"; });
  doc.addEventListener("keydown",(e)=>{ if(e.key==="Escape"){ modal.style.display="none"; closeAll(); } });
  $("#snModalClose").addEventListener("click",()=>modal.style.display="none");

  // Events
  const bellToggle = async()=>{ const wasOpen=!bellDD.hidden; closeAll(); bellDD.hidden = wasOpen; if(!wasOpen){ positionDropdown(bellDD,bellBtn); await loadNotifications(); } };
  const profToggle = ()=>{ const wasOpen=!profDD.hidden; closeAll(); profDD.hidden = wasOpen; if(!wasOpen) positionDropdown(profDD,profBtn); };

  bellBtn.addEventListener("click", bellToggle);
  bellBtn.addEventListener("keydown",(e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); bellToggle(); }});
  profBtn.addEventListener("click", profToggle);
  profBtn.addEventListener("keydown",(e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); profToggle(); }});
  doc.addEventListener("click",(e)=>{ if(!tray.contains(e.target) && !bellDD.contains(e.target) && !profDD.contains(e.target)) closeAll(); });

  markAllBtn?.addEventListener("click", async()=>{ if(!isAuthed) return; try{ await postJSON("/api/notifications/mark-all-read"); }catch{} notifications.forEach(n=>n.read=true); renderList(); });
  logoutBtn?.addEventListener("click", async()=>{ try{await postJSON("/api/logout");}catch{} isAuthed=false; role="user"; toggleAuthLinks(false); location.href="/li"; });

  // Init
  loadSession();
})();
