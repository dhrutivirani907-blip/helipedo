const express=require("express");
const cors=require("cors");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const {Pool}=require("pg");
const crypto=require("crypto");

const app=express();
const PORT=process.env.PORT||10000;
const DATABASE_URL=process.env.DATABASE_URL;
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;
const SESSION_SECRET=process.env.SESSION_SECRET;
if(!DATABASE_URL)throw new Error("DATABASE_URL environment variable is required");
if(!ADMIN_PASSWORD)throw new Error("ADMIN_PASSWORD environment variable is required");
if(!SESSION_SECRET)throw new Error("SESSION_SECRET environment variable is required");

const pool=new Pool({connectionString:DATABASE_URL,ssl:{rejectUnauthorized:false},max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
app.set("trust proxy",1);
app.use(helmet({crossOriginResourcePolicy:false}));
const ALLOWED_ORIGINS=new Set(["https://dhrutivirani907-blip.github.io","http://localhost:3000","http://localhost:5173","http://127.0.0.1:3000","http://127.0.0.1:5173"]);
app.use(cors({origin(o,cb){if(!o||ALLOWED_ORIGINS.has(o))return cb(null,true);return cb(new Error("Origin is not allowed by CORS"));},credentials:false,methods:["GET","POST","OPTIONS"],allowedHeaders:["Content-Type","X-Account-Token","X-Admin-Token"],optionsSuccessStatus:204}));
app.use(express.json({limit:"30kb"}));
app.use("/api/",rateLimit({windowMs:60000,limit:180,standardHeaders:true,legacyHeaders:false}));
const AD_MIN_WATCH_MS=12000;
const AD_REWARD=30;
const AD_COOLDOWN_MS=30000;
const TAP_REWARD=0;
const REF_REWARD=500;
const MIN_WITHDRAW=500;

function normalize(v){return String(v??"").trim().replace(/\s+/g," ")}
function validName(v){return v.length>=2&&v.length<=40&&/^[\p{L}\p{N} ._-]+$/u.test(v)}
function sign(v){return crypto.createHmac("sha256",SESSION_SECRET).update(v).digest("hex")}
function tokenFor(id){const p=`${id}.${Date.now()}`;return `${p}.${sign(p)}`}
function verifyToken(t){try{if(!t)return null;const p=String(t).split(".");if(p.length!==3)return null;const[id,issued,sig]=p;if(!/^\d+$/.test(id)||!/^\d+$/.test(issued))return null;if(Date.now()-Number(issued)>180*24*60*60*1000)return null;const exp=sign(`${id}.${issued}`);if(sig.length!==exp.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(exp)))return null;return Number(id)}catch{return null}}
function accountId(req){return verifyToken(req.headers["x-account-token"])}
async function payload(id){
 const r=await pool.query(`SELECT id,name,coin_balance,ads_count,ad_earnings,referrals_count,tap_count,ref_code,created_at,last_active_at,cooldown_until
 FROM job_accounts WHERE id=$1 AND is_active=TRUE`,[id]);
 if(!r.rows[0])return null;const x=r.rows[0];
 return {id:Number(x.id),name:x.name,coinBalance:Number(x.coin_balance||0),adsCount:Number(x.ads_count||0),adEarnings:Number(x.ad_earnings||0),referralsCount:Number(x.referrals_count||0),tapCount:Number(x.tap_count||0),cooldownUntil:x.cooldown_until?new Date(x.cooldown_until).getTime():0,refCode:x.ref_code,createdAt:x.created_at,lastActiveAt:x.last_active_at};
}
async function requireAccount(req,res,next){const id=accountId(req);if(!id)return res.status(401).json({ok:false,error:"Account session expired. Please enter your name again."});try{const a=await payload(id);if(!a)return res.status(401).json({ok:false,error:"Account not found."});req.account=a;await pool.query("UPDATE job_accounts SET last_active_at=NOW() WHERE id=$1",[id]);next()}catch(e){console.error(e);res.status(500).json({ok:false,error:"Server error."})}}
function requireAdmin(req,res,next){const t=String(req.headers["x-admin-token"]||"");const exp=sign("admin:"+ADMIN_PASSWORD);try{if(!t||t.length!==exp.length||!crypto.timingSafeEqual(Buffer.from(t),Buffer.from(exp)))return res.status(401).json({ok:false,error:"Admin authentication required."});next()}catch{return res.status(401).json({ok:false,error:"Admin authentication required."})}}

async function initDb(){
 await pool.query(`CREATE TABLE IF NOT EXISTS job_accounts(
 id BIGSERIAL PRIMARY KEY,name VARCHAR(40) NOT NULL,name_key VARCHAR(40) NOT NULL,
 coin_balance BIGINT NOT NULL DEFAULT 0 CHECK(coin_balance>=0),ads_count BIGINT NOT NULL DEFAULT 0 CHECK(ads_count>=0),ad_earnings BIGINT NOT NULL DEFAULT 0 CHECK(ad_earnings>=0),
 referrals_count INTEGER NOT NULL DEFAULT 0 CHECK(referrals_count>=0),tap_count INTEGER NOT NULL DEFAULT 0 CHECK(tap_count BETWEEN 0 AND 3),
 ref_code VARCHAR(80) UNIQUE,referrer_id BIGINT REFERENCES job_accounts(id),is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 for(const sql of [
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS coin_balance BIGINT NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS ads_count BIGINT NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS ad_earnings BIGINT NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS referrals_count INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS tap_count INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS ref_code VARCHAR(80)",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS referrer_id BIGINT",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS daily_ads_count INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS daily_ads_date DATE",
  "ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMPTZ"
 ]){try{await pool.query(sql)}catch(e){if(!String(e.message).includes("already exists"))throw e}}
 // Allow multiple accounts to use the same display name. Remove the legacy unique constraint.
 await pool.query("ALTER TABLE job_accounts DROP CONSTRAINT IF EXISTS job_accounts_name_key_key");
 await pool.query("DROP INDEX IF EXISTS job_accounts_name_key_key");
 // The fourth tap is a valid state while the user completes the ad step.
 await pool.query("ALTER TABLE job_accounts DROP CONSTRAINT IF EXISTS job_accounts_tap_count_check");
 await pool.query("ALTER TABLE job_accounts ADD CONSTRAINT job_accounts_tap_count_check CHECK(tap_count BETWEEN 0 AND 4)");
 // Keep ad sessions in PostgreSQL so Render restarts do not invalidate a user's 4/4 cycle.
 await pool.query(`CREATE TABLE IF NOT EXISTS tap_ad_sessions(
  account_id BIGINT PRIMARY KEY REFERENCES job_accounts(id) ON DELETE CASCADE,
  ad_token VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ
 )`);
 await pool.query(`CREATE TABLE IF NOT EXISTS reward_ad_sessions(
  account_id BIGINT PRIMARY KEY REFERENCES job_accounts(id) ON DELETE CASCADE,
  ad_token VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ
 )`);
 await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS job_accounts_ref_code_idx ON job_accounts(ref_code) WHERE ref_code IS NOT NULL`);
 await pool.query(`CREATE TABLE IF NOT EXISTS withdrawals(
 id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES job_accounts(id) ON DELETE CASCADE,
 binance_id VARCHAR(120) NOT NULL,amount BIGINT NOT NULL CHECK(amount>=1000000),
 status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed','rejected')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query(`CREATE TABLE IF NOT EXISTS tasks(
 id BIGSERIAL PRIMARY KEY,name VARCHAR(120) NOT NULL,link TEXT NOT NULL,reward BIGINT NOT NULL CHECK(reward>0),
 is_active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query(`CREATE TABLE IF NOT EXISTS task_claims(
 id BIGSERIAL PRIMARY KEY,task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 account_id BIGINT NOT NULL REFERENCES job_accounts(id) ON DELETE CASCADE,claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(task_id,account_id))`);
 await pool.query("UPDATE tasks SET reward=200 WHERE reward=3000000");
 await pool.query(`CREATE TABLE IF NOT EXISTS live_payments(
 id BIGSERIAL PRIMARY KEY,amount BIGINT NOT NULL CHECK(amount>0),channel_link TEXT NOT NULL DEFAULT 'https://t.me/bonk_taping',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query(`CREATE INDEX IF NOT EXISTS withdrawals_account_idx ON withdrawals(account_id,created_at DESC)`);
 await pool.query(`CREATE INDEX IF NOT EXISTS task_claims_account_idx ON task_claims(account_id)`);
 // One-time BONK conversion migration: preserve accounts/referral codes, reset old BabyDoge earning state.
 await pool.query(`CREATE TABLE IF NOT EXISTS app_migrations(
  key VARCHAR(120) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`);
 const migration=await pool.query("SELECT 1 FROM app_migrations WHERE key=$1",["bonk_conversion_reset_v1"]);
 if(!migration.rows[0]){
  const client=await pool.connect();
  try{
   await client.query("BEGIN");
   await client.query(`UPDATE job_accounts SET coin_balance=0,ads_count=0,ad_earnings=0,referrals_count=0,tap_count=0,daily_ads_count=0,daily_ads_date=NULL,cooldown_until=NULL,updated_at=NOW()`);
   await client.query("DELETE FROM reward_ad_sessions");
   await client.query("DELETE FROM tap_ad_sessions");
   await client.query("DELETE FROM task_claims");
   await client.query("DELETE FROM withdrawals");
   await client.query("DELETE FROM live_payments");
   await client.query("INSERT INTO app_migrations(key) VALUES($1)",["bonk_conversion_reset_v1"]);
   await client.query("COMMIT");
   console.log("BONK conversion migration applied: old BabyDoge earning state reset.");
  }catch(e){try{await client.query("ROLLBACK")}catch{}throw e}finally{client.release()}
 }
}

app.get("/",(req,res)=>res.json({status:"Active",app:"BONK Rewards Backend",database:"Connected API",version:"5.0.0"}));
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,status:"healthy"})}catch{res.status(503).json({ok:false,status:"database_unavailable"})}});
app.get("/api/session",async(req,res)=>{const id=accountId(req);if(!id)return res.json({ok:true,hasSession:false});try{res.json({ok:true,hasSession:!!(await payload(id))})}catch{res.status(500).json({ok:false,error:"Server error."})}});

app.post("/api/account",async(req,res)=>{
 const name=normalize(req.body?.name);if(!validName(name))return res.status(400).json({ok:false,error:"Please enter a valid name (2-40 characters)."});
 const key=name.toLocaleLowerCase("en-US");const refCode=normalize(req.body?.refCode);let referrerId=null;
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  if(refCode){const rr=await client.query("SELECT id FROM job_accounts WHERE ref_code=$1 AND is_active=TRUE",[refCode]);if(rr.rows[0])referrerId=rr.rows[0].id}
  const code=crypto.randomBytes(8).toString("hex");
  const created=await client.query(`INSERT INTO job_accounts(name,name_key,ref_code,referrer_id) VALUES($1,$2,$3,$4) RETURNING id`,[name,key,code,referrerId]);
  const id=created.rows[0].id;
  if(referrerId){await client.query("UPDATE job_accounts SET referrals_count=referrals_count+1,coin_balance=coin_balance+$1,updated_at=NOW() WHERE id=$2",[REF_REWARD,referrerId])}
  await client.query("COMMIT");
  res.status(201).json({ok:true,sessionToken:tokenFor(id),account:await payload(id)});
 }catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not create account."})}finally{client.release()}
});
app.get("/api/account/me",requireAccount,(req,res)=>res.json({ok:true,account:req.account}));

app.post("/api/tap",requireAccount,async(req,res)=>{
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  const r=await client.query("SELECT tap_count,cooldown_until FROM job_accounts WHERE id=$1 AND is_active=TRUE FOR UPDATE",[req.account.id]);
  if(!r.rows[0]){await client.query("ROLLBACK");return res.status(404).json({ok:false,error:"Account not found."})}
  if(r.rows[0].cooldown_until&&new Date(r.rows[0].cooldown_until).getTime()>Date.now()){
   const until=new Date(r.rows[0].cooldown_until).getTime();await client.query("ROLLBACK");return res.status(429).json({ok:false,error:"Tap locked. Please wait for the cooldown to finish.",cooldownUntil:until});
  }
  const current=Number(r.rows[0].tap_count||0);
  if(current>=4){await client.query("ROLLBACK");return res.status(409).json({ok:false,error:"Complete the current ad cycle first."})}
  const next=current+1;
  if(next<4){
   await client.query("UPDATE job_accounts SET tap_count=$1,coin_balance=coin_balance+$2,last_active_at=NOW(),updated_at=NOW() WHERE id=$3",[next,TAP_REWARD,req.account.id]);
   await client.query("COMMIT");return res.json({ok:true,adRequired:false,account:await payload(req.account.id)});
  }
  await client.query("UPDATE job_accounts SET tap_count=4,coin_balance=coin_balance+$1,last_active_at=NOW(),updated_at=NOW() WHERE id=$2",[TAP_REWARD,req.account.id]);
  const adToken=crypto.randomBytes(24).toString("hex");
  await client.query("INSERT INTO tap_ad_sessions(account_id,ad_token,created_at,started_at) VALUES($1,$2,NOW(),NULL) ON CONFLICT(account_id) DO UPDATE SET ad_token=EXCLUDED.ad_token,created_at=NOW(),started_at=NULL",[req.account.id,adToken]);
  await client.query("COMMIT");res.json({ok:true,adRequired:true,adToken,account:await payload(req.account.id)});
 }catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not process tap."})}finally{client.release()}
});
app.get("/api/tap/ad-session",requireAccount,async(req,res)=>{
 try{
  const a=await pool.query("SELECT tap_count FROM job_accounts WHERE id=$1 AND is_active=TRUE",[req.account.id]);
  if(!a.rows[0]||Number(a.rows[0].tap_count)!==4)return res.status(409).json({ok:false,error:"Complete the 4-tap cycle first."});
  let r=await pool.query("SELECT ad_token,started_at FROM tap_ad_sessions WHERE account_id=$1",[req.account.id]);
  if(!r.rows[0]){
   const freshToken=crypto.randomBytes(24).toString("hex");
   await pool.query("INSERT INTO tap_ad_sessions(account_id,ad_token) VALUES($1,$2) ON CONFLICT(account_id) DO NOTHING",[req.account.id,freshToken]);
   r=await pool.query("SELECT ad_token,started_at FROM tap_ad_sessions WHERE account_id=$1",[req.account.id]);
  }
  res.json({ok:true,adToken:r.rows[0].ad_token,startedAt:r.rows[0].started_at?new Date(r.rows[0].started_at).getTime():0});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not restore ad session."})}
});
app.post("/api/tap/ad-start",requireAccount,async(req,res)=>{
 const adToken=String(req.body?.adToken||"");
 if(!adToken)return res.status(400).json({ok:false,error:"Ad session is missing. Please reopen the ad step."});
 try{
  const r=await pool.query(`UPDATE tap_ad_sessions s SET started_at=NOW()
   FROM job_accounts a WHERE s.account_id=$1 AND s.account_id=a.id AND a.tap_count=4 AND s.ad_token=$2
   RETURNING s.started_at`,[req.account.id,adToken]);
  if(!r.rows[0])return res.status(400).json({ok:false,error:"Ad session is invalid. Please reopen the ad step."});
  res.json({ok:true,started:true,startedAt:new Date(r.rows[0].started_at).getTime()});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not start ad session."})}
});
app.post("/api/tap/reset",requireAccount,async(req,res)=>{
 const adToken=String(req.body?.adToken||"");if(!adToken)return res.status(400).json({ok:false,error:"Ad session is missing."});
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  const session=await client.query("SELECT started_at FROM tap_ad_sessions WHERE account_id=$1 AND ad_token=$2 FOR UPDATE",[req.account.id,adToken]);
  if(!session.rows[0]){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Ad session is invalid. Please reopen the ad step."})}
  if(!session.rows[0].started_at){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Please open the ad first."})}
  const elapsed=Date.now()-new Date(session.rows[0].started_at).getTime();
  if(elapsed<AD_MIN_WATCH_MS){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Watch ads for at least 10 seconds before resetting progress."})}
  const updated=await client.query(`UPDATE job_accounts
   SET tap_count=0,ads_count=ads_count+1,
       cooldown_until=CASE WHEN (ads_count+1)%10=0 THEN NOW()+INTERVAL '1 minute' ELSE cooldown_until END,
       updated_at=NOW()
   WHERE id=$1 AND tap_count=4 RETURNING id,ads_count,cooldown_until`,[req.account.id]);
  if(!updated.rows[0]){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Tap cycle is not ready to reset."})}
  await client.query("DELETE FROM tap_ad_sessions WHERE account_id=$1",[req.account.id]);
  await client.query("COMMIT");res.json({ok:true,account:await payload(req.account.id)});
 }catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not reset tap progress."})}finally{client.release()}
});

app.post("/api/reward-ad/start",requireAccount,async(req,res)=>{
 const now=Date.now();
 try{
  const a=await pool.query("SELECT cooldown_until FROM job_accounts WHERE id=$1 AND is_active=TRUE",[req.account.id]);
  if(!a.rows[0])return res.status(404).json({ok:false,error:"Account not found."});
  if(a.rows[0].cooldown_until&&new Date(a.rows[0].cooldown_until).getTime()>now){
   return res.status(429).json({ok:false,error:"Please wait for the 30-second cooldown to finish.",cooldownUntil:new Date(a.rows[0].cooldown_until).getTime()});
  }
  let r=await pool.query("SELECT ad_token,started_at FROM reward_ad_sessions WHERE account_id=$1",[req.account.id]);
  if(r.rows[0]&&r.rows[0].started_at&&now-new Date(r.rows[0].started_at).getTime()<10*60*1000){
   return res.json({ok:true,adToken:r.rows[0].ad_token,startedAt:new Date(r.rows[0].started_at).getTime()});
  }
  const adToken=crypto.randomBytes(24).toString("hex");
  await pool.query(`INSERT INTO reward_ad_sessions(account_id,ad_token,created_at,started_at) VALUES($1,$2,NOW(),NOW())
   ON CONFLICT(account_id) DO UPDATE SET ad_token=EXCLUDED.ad_token,created_at=NOW(),started_at=NOW()`,[req.account.id,adToken]);
  const x=await pool.query("SELECT started_at FROM reward_ad_sessions WHERE account_id=$1",[req.account.id]);
  res.json({ok:true,adToken,startedAt:new Date(x.rows[0].started_at).getTime()});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not start rewarded ad."})}
});

app.post("/api/reward-ad/complete",requireAccount,async(req,res)=>{
 const adToken=String(req.body?.adToken||"");if(!adToken)return res.status(400).json({ok:false,error:"Ad session is missing."});
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  const session=await client.query("SELECT started_at FROM reward_ad_sessions WHERE account_id=$1 AND ad_token=$2 FOR UPDATE",[req.account.id,adToken]);
  if(!session.rows[0]){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Ad session is invalid or already completed."})}
  if(!session.rows[0].started_at){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Please start the ad first."})}
  const elapsed=Date.now()-new Date(session.rows[0].started_at).getTime();
  if(elapsed<AD_MIN_WATCH_MS){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Watch ads for at least 12 seconds before claiming the reward."})}
  const updated=await client.query(`UPDATE job_accounts
   SET coin_balance=coin_balance+$1,ads_count=ads_count+1,ad_earnings=ad_earnings+$1,
       cooldown_until=NOW()+INTERVAL '30 seconds',last_active_at=NOW(),updated_at=NOW()
   WHERE id=$2 AND is_active=TRUE RETURNING id`,[AD_REWARD,req.account.id]);
  if(!updated.rows[0]){await client.query("ROLLBACK");return res.status(404).json({ok:false,error:"Account not found."})}
  await client.query("DELETE FROM reward_ad_sessions WHERE account_id=$1",[req.account.id]);
  await client.query("COMMIT");
  res.json({ok:true,account:await payload(req.account.id)});
 }catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not add the ad reward."})}finally{client.release()}
});

app.post("/api/withdrawals",requireAccount,async(req,res)=>{
 const binanceId=normalize(req.body?.binanceId),amount=Number(req.body?.amount);
 if(!binanceId||binanceId.length>120)return res.status(400).json({ok:false,error:"Enter a valid Binance ID."});
 if(!Number.isSafeInteger(amount)||amount<MIN_WITHDRAW)return res.status(400).json({ok:false,error:"Minimum withdrawal is 500 BONK."});
 const client=await pool.connect();
 try{await client.query("BEGIN");const r=await client.query("UPDATE job_accounts SET coin_balance=coin_balance-$1,updated_at=NOW() WHERE id=$2 AND coin_balance >= $1 RETURNING id",[amount,req.account.id]);if(!r.rows[0]){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"Insufficient BONK balance."})}
 await client.query("INSERT INTO withdrawals(account_id,binance_id,amount) VALUES($1,$2,$3)",[req.account.id,binanceId,amount]);await client.query("COMMIT");res.json({ok:true,account:await payload(req.account.id)})}
 catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not submit withdrawal."})}finally{client.release()}
});
app.get("/api/withdrawals",requireAccount,async(req,res)=>{try{const r=await pool.query("SELECT id,binance_id,amount,status,created_at FROM withdrawals WHERE account_id=$1 ORDER BY created_at DESC",[req.account.id]);res.json({ok:true,items:r.rows.map(x=>({id:Number(x.id),binanceId:x.binance_id,amount:Number(x.amount),status:x.status,createdAt:x.created_at}))})}catch{res.status(500).json({ok:false,error:"Could not load withdrawals."})}});

app.get("/api/tasks",requireAccount,async(req,res)=>{try{const r=await pool.query(`SELECT t.id,t.name,t.link,t.reward,EXISTS(SELECT 1 FROM task_claims c WHERE c.task_id=t.id AND c.account_id=$1) claimed FROM tasks t WHERE t.is_active=TRUE ORDER BY t.created_at DESC`,[req.account.id]);res.json({ok:true,tasks:r.rows.map(x=>({id:Number(x.id),name:x.name,link:x.link,reward:Number(x.reward),claimed:x.claimed}))})}catch{res.status(500).json({ok:false,error:"Could not load tasks."})}});
app.post("/api/tasks/:id/claim",requireAccount,async(req,res)=>{
 const id=Number(req.params.id);const client=await pool.connect();
 try{await client.query("BEGIN");const t=await client.query("SELECT reward FROM tasks WHERE id=$1 AND is_active=TRUE FOR UPDATE",[id]);if(!t.rows[0]){await client.query("ROLLBACK");return res.status(404).json({ok:false,error:"Task not found."})}
 const c=await client.query("SELECT id FROM task_claims WHERE task_id=$1 AND account_id=$2",[id,req.account.id]);if(c.rows[0]){await client.query("ROLLBACK");return res.status(409).json({ok:false,error:"Task already claimed."})}
 const reward=Number(t.rows[0].reward);await client.query("INSERT INTO task_claims(task_id,account_id) VALUES($1,$2)",[id,req.account.id]);await client.query("UPDATE job_accounts SET coin_balance=coin_balance+$1,updated_at=NOW() WHERE id=$2",[reward,req.account.id]);await client.query("COMMIT");res.json({ok:true,account:await payload(req.account.id)})}
 catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not claim task."})}finally{client.release()}
});
app.get("/api/payments",requireAccount,async(req,res)=>{res.json({ok:true,items:[]})});

app.post("/api/admin/login",rateLimit({windowMs:10*60*1000,limit:20}),async(req,res)=>{const p=String(req.body?.password||"");const a=Buffer.from(p),b=Buffer.from(ADMIN_PASSWORD);if(!p||a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({ok:false,error:"Incorrect admin password."});res.json({ok:true,adminToken:sign("admin:"+ADMIN_PASSWORD)})});
app.get("/api/admin/withdrawals",requireAdmin,async(req,res)=>{const r=await pool.query(`SELECT w.id,w.binance_id,w.amount,w.status,w.created_at,a.name FROM withdrawals w JOIN job_accounts a ON a.id=w.account_id ORDER BY w.created_at DESC`);res.json({ok:true,items:r.rows.map(x=>({id:Number(x.id),name:x.name,binanceId:x.binance_id,amount:Number(x.amount),status:x.status,createdAt:x.created_at}))})});
app.post("/api/admin/withdrawals/:id",requireAdmin,async(req,res)=>{const status=String(req.body?.status||"");if(!["pending","completed","rejected"].includes(status))return res.status(400).json({ok:false,error:"Invalid status."});const client=await pool.connect();try{await client.query("BEGIN");const w=await client.query("SELECT account_id,amount,status FROM withdrawals WHERE id=$1 FOR UPDATE",[req.params.id]);if(!w.rows[0]){await client.query("ROLLBACK");return res.status(404).json({ok:false,error:"Withdrawal not found."})}
 const old=w.rows[0].status;if(old!==status){if(old==="pending"&&status==="rejected")await client.query("UPDATE job_accounts SET coin_balance=coin_balance+$1 WHERE id=$2",[w.rows[0].amount,w.rows[0].account_id]);if(old==="rejected"&&status==="pending")await client.query("UPDATE job_accounts SET coin_balance=coin_balance-$1 WHERE id=$2 AND coin_balance >= $1",[w.rows[0].amount,w.rows[0].account_id]);}
 await client.query("UPDATE withdrawals SET status=$1,updated_at=NOW() WHERE id=$2",[status,req.params.id]);await client.query("COMMIT");res.json({ok:true})}catch(e){try{await client.query("ROLLBACK")}catch{}res.status(500).json({ok:false,error:"Could not update withdrawal."})}finally{client.release()}});
app.get("/api/admin/tasks",requireAdmin,async(req,res)=>{const r=await pool.query("SELECT id,name,link,reward,is_active FROM tasks ORDER BY created_at DESC");res.json({ok:true,tasks:r.rows.map(x=>({id:Number(x.id),name:x.name,link:x.link,reward:Number(x.reward),isActive:x.is_active}))})});
app.post("/api/admin/tasks",requireAdmin,async(req,res)=>{const name=normalize(req.body?.name),link=normalize(req.body?.link),reward=Number(req.body?.reward);if(!name||!/^https?:\/\//i.test(link)||!Number.isSafeInteger(reward)||reward<=0)return res.status(400).json({ok:false,error:"Enter valid task name, link and reward."});await pool.query("INSERT INTO tasks(name,link,reward) VALUES($1,$2,$3)",[name,link,reward]);res.json({ok:true})});
app.get("/api/admin/stats",requireAdmin,async(req,res)=>{const q=await Promise.all([pool.query("SELECT COUNT(*) n FROM job_accounts WHERE is_active=TRUE"),pool.query("SELECT COUNT(*) n FROM job_accounts WHERE is_active=TRUE AND last_active_at>NOW()-INTERVAL '24 hours'"),pool.query("SELECT COALESCE(SUM(coin_balance),0) n FROM job_accounts WHERE is_active=TRUE"),pool.query("SELECT COALESCE(SUM(ads_count),0) n FROM job_accounts WHERE is_active=TRUE"),pool.query("SELECT COALESCE(SUM(referrals_count),0) n FROM job_accounts WHERE is_active=TRUE"),pool.query("SELECT COUNT(*) n FROM withdrawals WHERE status='pending'")]);res.json({ok:true,users:Number(q[0].rows[0].n),activeUsers:Number(q[1].rows[0].n),totalCoins:Number(q[2].rows[0].n),totalAds:Number(q[3].rows[0].n),totalReferrals:Number(q[4].rows[0].n),pendingWithdrawals:Number(q[5].rows[0].n)})});
app.get("/api/admin/users",requireAdmin,async(req,res)=>{const r=await pool.query(`SELECT id,name,coin_balance,ads_count,ad_earnings,referrals_count,created_at,last_active_at FROM job_accounts WHERE is_active=TRUE ORDER BY created_at DESC`);res.json({ok:true,users:r.rows.map(x=>({id:Number(x.id),name:x.name,coinBalance:Number(x.coin_balance),adsCount:Number(x.ads_count),adEarnings:Number(x.ad_earnings||0),referralsCount:Number(x.referrals_count),createdAt:x.created_at,lastActiveAt:x.last_active_at}))})});
app.post("/api/admin/users/:id/reset",requireAdmin,async(req,res)=>{await pool.query("UPDATE job_accounts SET coin_balance=0,ads_count=0,ad_earnings=0,referrals_count=0,tap_count=0,cooldown_until=NULL,updated_at=NOW() WHERE id=$1",[req.params.id]);res.json({ok:true})});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({ok:false,error:"Unexpected server error."})});
initDb().then(()=>app.listen(PORT,()=>console.log(`BONK backend running on port ${PORT}`))).catch(e=>{console.error("Database initialization failed:",e);process.exit(1)});
