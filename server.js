
  const API_BASE = "https://helipedo.onrender.com";
  const AD_URL = "https://asiafilm.org/4/17d6a856c8a2251142b070b3c3d63131";
  const MIN_SECONDS = 8, BREAK_SECONDS = 120, EVERY_ADS = 100;

  const countEl = document.getElementById("count");
  const watchBtn = document.getElementById("watch");
  const bar = document.getElementById("bar");
  const progressNum = document.getElementById("progressNum");
  const progressLabel = document.getElementById("progressLabel");
  const statusEl = document.getElementById("status");
  const accountNameEl = document.getElementById("accountName");

  const accountModal = document.getElementById("accountModal");
  const checkingModal = document.getElementById("checkingModal");
  const profileModal = document.getElementById("profileModal");
  const adminLoginModal = document.getElementById("adminLoginModal");
  const adminModal = document.getElementById("adminModal");

  let account = null;
  let pending = null;
  let breakUntil = 0;
  let tickTimer = null;
  let toastTimer = null;
  let adminToken = null;
  let leftPageForAd = false;
  let checkingReturn = false;

  function show(el){el.classList.add("show")}
  function hide(el){el.classList.remove("show")}
  function toast(msg){
    const el=document.getElementById("toast");
    el.textContent=msg;el.classList.add("show");
    clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove("show"),2500);
  }
  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
  }
  async function api(path, options={}){
    const opts={...options,credentials:"include",headers:{"Content-Type":"application/json",...(options.headers||{})}};
    const response=await fetch(API_BASE+path,opts);
    let data=null;
    try{data=await response.json()}catch{}
    if(!response.ok) throw new Error(data?.error || "Server request failed.");
    return data;
  }

  function secondsLeft(){return Math.max(0,Math.ceil((breakUntil-Date.now())/1000))}
  function formatTime(sec){const m=Math.floor(sec/60),s=sec%60;return `${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`}

  function render(){
    const count=Number(account?.adsCount||0);
    countEl.textContent=count.toLocaleString();
    const progress=count%EVERY_ADS;
    bar.style.width=progress+"%";
    progressNum.textContent=`${progress} / ${EVERY_ADS}`;
    accountNameEl.textContent=account?.name||"Not connected";
    const left=secondsLeft();
    if(left>0){
      watchBtn.disabled=true;
      watchBtn.innerHTML=`<span class="button-icon">🔒</span>Break · ${formatTime(left)}`;
      progressLabel.textContent="Break timer";
    }else{
      watchBtn.disabled=!account || !!pending;
      watchBtn.innerHTML=pending
        ? '<span class="button-icon">↗</span>Ad opened…'
        : '<span class="button-icon">▶</span>Watch Ads';
      progressLabel.textContent="Progress to break";
    }
    document.getElementById("profileInfo").textContent=account
      ? `Name: ${account.name}\nTotal ads: ${Number(account.adsCount).toLocaleString()}`
      : "No account connected.";
  }

  async function refreshAccount(){
    try{
      const data=await api("/api/account/me");
      account=data.account;
      statusEl.textContent="SECURE • ONLINE";
      render();
      return true;
    }catch{
      account=null;
      statusEl.textContent="ACCOUNT REQUIRED";
      render();
      return false;
    }
  }

  async function boot(){
    try{
      const session=await api("/api/session");
      if(session.hasSession){
        // Requirement: popup appears every time. Returning users get Check.
        document.getElementById("accountTitle").textContent="Enter Your Name";
        document.getElementById("accountText").textContent="Enter the same name used for your backend job account.";
        document.getElementById("accountAction").textContent="Check";
        document.getElementById("accountError").textContent="";
        show(accountModal);
      }else{
        document.getElementById("accountTitle").textContent="Enter Your Name";
        document.getElementById("accountText").textContent="Create your job account. Your ad count will be stored securely on the server.";
        document.getElementById("accountAction").textContent="Save";
        document.getElementById("accountError").textContent="";
        show(accountModal);
      }
      statusEl.textContent="READY";
    }catch{
      statusEl.textContent="SERVER ERROR";
      toast("Could not connect to backend.");
      show(accountModal);
    }
    render();
  }

  async function saveOrCheck(){
    const input=document.getElementById("nameInput");
    const error=document.getElementById("accountError");
    const name=input.value.trim();
    if(name.length<2){error.textContent="Please enter your name.";return}
    const action=document.getElementById("accountAction");
    action.disabled=true; error.textContent="";
    hide(accountModal); show(checkingModal);

    try{
      // Determine mode from whether a backend session exists.
      const session=await api("/api/session");
      const endpoint=session.hasSession ? "/api/account/check" : "/api/account";
      const data=await api(endpoint,{method:"POST",body:JSON.stringify({name})});
      account=data.account;
      breakUntil=0;
      hide(checkingModal);
      statusEl.textContent="SECURE • ONLINE";
      render();
      toast(session.hasSession ? "Account verified." : "Account created successfully.");
    }catch(err){
      hide(checkingModal);
      error.textContent=err.message;
      show(accountModal);
    }finally{
      action.disabled=false;
    }
  }

  function openAd(){
    if(!account || pending || secondsLeft()>0)return;
    const started=Date.now();
    pending={started};
    const opened=window.open(AD_URL,"_blank");
    if(!opened){
      pending=null;render();
      toast("Please allow pop-ups, then tap Watch Ads again.");
      return;
    }
    render();
  }

  function showAdResult(success, message){
    const icon=document.getElementById("resultIcon");
    icon.className="modal-icon "+(success?"success":"failure");
    icon.textContent=success?"✓":"!";
    document.getElementById("resultTitle").textContent=success?"Ad Count Updated":"Count Not Updated";
    document.getElementById("resultText").textContent=message;
    show(document.getElementById("resultModal"));
  }

  async function checkReturn(){
    if(!pending || checkingReturn || document.visibilityState==="hidden")return;
    checkingReturn=true;
    const elapsed=(Date.now()-pending.started)/1000;
    pending=null;
    leftPageForAd=false;

    if(elapsed<MIN_SECONDS){
      checkingReturn=false;
      render();
      showAdResult(false,"Watch ads for a minimum of 8 seconds. Your ad count has not been updated.");
      return;
    }

    try{
      const data=await api("/api/account/me/increment-ad",{method:"POST",body:"{}"});
      account=data.account;
      if(account.adsCount % EVERY_ADS===0){
        breakUntil=Date.now()+BREAK_SECONDS*1000;
        render();
        showAdResult(true,"1 ad counted successfully. You completed 100 ads, so your 2-minute break has started.");
      }else{
        render();
        showAdResult(true,"1 ad counted successfully. Your total ad count has been updated.");
      }
    }catch(err){
      render();
      showAdResult(false,err.message||"Your ad count could not be updated. Please try again.");
    }finally{
      checkingReturn=false;
      render();
    }
  }

  async function adminLogin(){
    const password=document.getElementById("adminPassword").value;
    const error=document.getElementById("adminError");
    if(!password){error.textContent="Enter the admin password.";return}
    error.textContent="";
    try{
      const data=await api("/api/admin/login",{method:"POST",body:JSON.stringify({password})});
      adminToken=data.adminToken;
      document.getElementById("adminPassword").value="";
      hide(adminLoginModal);
      show(adminModal);
      await loadUsers();
    }catch(err){error.textContent=err.message}
  }

  async function loadUsers(){
    const list=document.getElementById("adminList");
    const summary=document.getElementById("adminSummary");
    list.innerHTML="<div class='small'>Loading users...</div>";
    try{
      const data=await api("/api/admin/users",{headers:{"x-admin-token":adminToken}});
      summary.textContent=`${data.users.length} registered user${data.users.length===1?"":"s"}`;
      if(!data.users.length){list.innerHTML="<div class='small'>No users yet.</div>";return}
      list.innerHTML=data.users.map(user=>`
        <div class="user-row">
          <div class="user-info">
            <div class="user-name">${escapeHtml(user.name)}</div>
            <div class="user-ads">${Number(user.adsCount).toLocaleString()} ads watched</div>
          </div>
          <button class="reset" data-reset="${user.id}">Reset</button>
        </div>
      `).join("");
      list.querySelectorAll("[data-reset]").forEach(btn=>{
        btn.addEventListener("click",()=>resetUser(btn.dataset.reset,btn));
      });
    }catch(err){
      summary.textContent="Unable to load users.";
      list.innerHTML=`<div class="small error">${escapeHtml(err.message)}</div>`;
    }
  }

  async function resetUser(id,btn){
    if(!confirm("Reset this user's total ad count to 0?"))return;
    btn.disabled=true;
    try{
      await api("/api/admin/users/"+encodeURIComponent(id)+"/reset",{
        method:"POST",
        headers:{"x-admin-token":adminToken},
        body:"{}"
      });
      toast("User ad count reset to 0.");
      if(account && String(account.id)===String(id)){
        account.adsCount=0;breakUntil=0;render();
      }
      await loadUsers();
    }catch(err){toast(err.message);btn.disabled=false}
  }

  document.getElementById("accountAction").addEventListener("click",saveOrCheck);
  document.getElementById("nameInput").addEventListener("keydown",e=>{if(e.key==="Enter")saveOrCheck()});
  document.getElementById("watch").addEventListener("click",openAd);

  document.getElementById("profileBtn").addEventListener("click",()=>show(profileModal));
  document.getElementById("profileClose").addEventListener("click",()=>hide(profileModal));
  document.getElementById("adminOpen").addEventListener("click",()=>{hide(profileModal);show(adminLoginModal)});
  document.getElementById("adminLoginClose").addEventListener("click",()=>hide(adminLoginModal));
  document.getElementById("adminLogin").addEventListener("click",adminLogin);
  document.getElementById("adminPassword").addEventListener("keydown",e=>{if(e.key==="Enter")adminLogin()});
  document.getElementById("adminClose").addEventListener("click",()=>hide(adminModal));
  document.getElementById("adminRefresh").addEventListener("click",loadUsers);

  document.getElementById("logoutBtn").addEventListener("click",async()=>{
    try{await api("/api/logout",{method:"POST"})}catch{}
    account=null;adminToken=null;
    hide(profileModal);
    document.getElementById("accountTitle").textContent="Enter Your Name";
    document.getElementById("accountText").textContent="Create your job account. Your ad count will be stored securely on the server.";
    document.getElementById("accountAction").textContent="Save";
    document.getElementById("nameInput").value="";
    render();show(accountModal);
  });

  document.addEventListener("visibilitychange",()=>{
    if(document.visibilityState==="hidden" && pending){
      leftPageForAd=true;
    }else if(document.visibilityState==="visible" && pending && leftPageForAd){
      checkReturn();
    }
  });
  window.addEventListener("focus",()=>{
    if(pending && leftPageForAd && document.visibilityState==="visible")checkReturn();
  });
  window.addEventListener("pageshow",()=>{
    if(pending && leftPageForAd && document.visibilityState==="visible")checkReturn();
  });
  document.getElementById("resultClose").addEventListener("click",()=>hide(document.getElementById("resultModal")));

  clearInterval(tickTimer);
  tickTimer=setInterval(()=>{
    if(breakUntil && secondsLeft()===0){breakUntil=0;toast("Break finished — unlocked!")}
    render();
  },500);

  boot();
})();
