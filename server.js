// server.js
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ====== ENV ======
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.API_TOKEN;          // n8n에서 X-API-Token으로 보낼 토큰
const KRI_UID = process.env.KRI_UID;              // KRI 아이디 (plain)
const KRI_UPW = process.env.KRI_UPW;              // KRI 비번 (plain, 특수문자 OK)
const KRI_ID_B64 = process.env.KRI_ID_B64;        // 예전 워크플로우에서 쓰던 값 (optional)
const KRI_PW_B64 = process.env.KRI_PW_B64;        // 예전 워크플로우에서 쓰던 값 (optional)

if (!API_TOKEN) console.warn("Missing API_TOKEN env");
if (!KRI_UID || !KRI_UPW) console.warn("Missing KRI_UID or KRI_UPW env");

// ====== Simple Auth Middleware ======
function auth(req, res, next) {
  const token = req.header("X-API-Token");
  if (!token || token !== API_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// ====== Cookie Jar (in-memory) ======
// Render 인스턴스 1개 기준으로는 충분. (스케일 아웃하면 Redis 같은 걸로 바꾸는 게 안전)
let jar = {
  wmonid: null,
  jsessionid: null,
  lastLoginAt: 0,
};

// ====== helpers ======
function now() { return Date.now(); }

function parseSetCookie(setCookieArr = []) {
  // set-cookie: ["WMONID=...; Path=/; ...", "JSESSIONID=...; Path=/; ...", ...]
  const out = {};
  for (const c of setCookieArr) {
    const first = c.split(";")[0];
    const [k, v] = first.split("=");
    if (k && v) out[k.trim()] = v.trim();
  }
  return out;
}

function cookieHeader() {
  const parts = [];
  if (jar.wmonid) parts.push(`WMONID=${jar.wmonid}`);
  if (jar.jsessionid) parts.push(`JSESSIONID=${jar.jsessionid}`);
  return parts.join("; ");
}

async function fetchFull(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  return { res, text };
}

// ====== KRI login flow ======
// 주의: 잦은 로그인은 차단/레이트리밋 가능. TTL로 최소화.
const LOGIN_TTL_MS = 1000 * 60 * 10; // 10분 (상황에 맞게 조절)

async function ensureLogin() {
  // 최근 로그인 했으면 재사용
  if (jar.jsessionid && now() - jar.lastLoginAt < LOGIN_TTL_MS) return;

  // 1) Get Cookie
  {
    const { res } = await fetchFull("https://www.kri.go.kr/kri2", {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "manual",
    });

    const setCookie = res.headers.getSetCookie?.() || res.headers.raw?.()["set-cookie"] || [];
    const parsed = parseSetCookie(setCookie);
    if (parsed.WMONID) jar.wmonid = parsed.WMONID;
    if (parsed.JSESSIONID) jar.jsessionid = parsed.JSESSIONID;
  }

  if (!jar.jsessionid) {
    throw new Error("Failed to obtain JSESSIONID from KRI");
  }

  // 2) CrossCert step (기존 워크플로우 흐름 유지)
  //    id/pw b64가 있으면 그것 사용, 없으면 plain을 b64로 만들어 사용
  const idB64 = KRI_ID_B64 || Buffer.from(KRI_UID, "utf8").toString("base64");
  const pwB64 = KRI_PW_B64 || Buffer.from(KRI_UPW, "utf8").toString("base64");

  await fetchFull("https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader(),
      "Origin": "https://www.kri.go.kr",
      "Referer": "https://www.kri.go.kr/kri2",
    },
    body: new URLSearchParams({
      id: idB64,
      pw: pwB64,
      loginCheck: "N",
      sysid: "KRI",
      skinColor: "sky_blue",
      type: "10",
      url: "https://www.kri.go.kr:443",
      uid: KRI_UID,
      upw: KRI_UPW,
      mbr_dvs_Cd: "null",
    }).toString(),
  });

  // 3) login_exec
  await fetchFull(
    `https://www.kri.go.kr/kri/rp/login_exec.jsp?txtLoginId=${encodeURIComponent(idB64)}&txtLogDvs=1&txtUserPw=${encodeURIComponent(pwB64)}&txtLoginDvs=I&txtAnotherLogin=N&txtAgree=1`,
    {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Cookie": cookieHeader(),
        "Referer": "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N",
      },
    }
  );

  // 4) 검색 페이지 진입 + requestOrder (예전 흐름 유지, 세션 안정화)
  await fetchFull("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Cookie": `potalHelpViewYn=Y; ${cookieHeader()}`,
      "Referer": "https://www.kri.go.kr/kri2",
    },
  });

  await fetchFull("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "X-Requested-With": "XMLHttpRequest",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "Cookie": `potalHelpViewYn=Y; ${cookieHeader()}`,
      "Referer": "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2",
    },
    body: "requestOrder",
  });

  jar.lastLoginAt = now();
}

// ====== Routes ======
app.get("/health", (req, res) => res.json({ ok: true }));

// (1) 이름/소속으로 KRI 모바일 검색 HTML 반환 (네가 지금 쓰는 것과 동일 목적)
app.post("/search", auth, async (req, res) => {
  try {
    const name = String(req.body?.name ?? "").trim();
    const org = String(req.body?.org ?? "").trim();

    await ensureLogin();

    // 모바일 검색 페이지 (네가 쓰던 m.kri.go.kr endpoint)
    const body = new URLSearchParams({
      mode: "firstSearch",
      txtSchNm: name,
      txtAgcNmP: org,
      agcCd: "",
      comcdSelVal: "",
      treeLev: "",
      comCdSel_lv1: "",
      comCdSel_lv2: "",
      comCdSel_lv3: "",
      comCdSel_lv4: "",
    }).toString();

    const { res: r, text: html } = await fetchFull("https://m.kri.go.kr/kri/mobile/PG-RP-101-01jl.jsp", {
      method: "POST",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        // 모바일쪽도 세션쿠키가 중요
        "Cookie": cookieHeader(),
        "Origin": "https://m.kri.go.kr",
        "Referer": "https://m.kri.go.kr/kri/mobile/KRI_RP_MO_001.jsp",
      },
      body,
    });

    res.json({ ok: true, kriStatus: r.status, html });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// (2) kri_id로 “연구비/과제(프로젝트)” 목록 가져오기  ← 예전 워크플로우의 핵심
app.post("/projects", auth, async (req, res) => {
  try {
    const kri_id = String(req.body?.kri_id ?? "").trim();
    if (!kri_id) return res.status(400).json({ ok: false, error: "Missing kri_id" });

    await ensureLogin();

    const requestOrder =
      "|RSCHR_REG_NO|MNG_NO|RSCH_CMCM_YM|RSCH_END_YM|RSRCCT_SPPT_DVS_CD|RSCH_SBJT_STDY_SPHE_CD|RSCH_SBJT_NM|RSRCCT_SPPT_AGC_NM|TOT_RSRCCT|SBJT_NO|MNY_YR_SBJT_YN|BIZ_NM|CPT_GOV_OFFIC_NM|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|MOD_DTTM|APPR_DVS_CD|APPR_RTRN_CNCL_RSN_CNTN|APPR_DTTM|DATA_SRC_DVS_CD|VRFC_DVS_CD|VRFC_DTTM|VRFC_PE_ID|VRFC_PE_NM|BLNG_UNIV_CD";

    const body = new URLSearchParams({
      requestOrder,
      sheetAcation: "F",
      txtRschrRegNo: kri_id,
    }).toString();

    const { res: r, text: xmlText } = await fetchFull("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-110-01js.jsp", {
      method: "POST",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": `JSESSIONID=${jar.jsessionid}`, // 예전 워크플로우와 동일
      },
      body,
    });

    // 여기서는 일단 XML 원문을 그대로 반환 (n8n에서 XML 노드+Code23로 파싱 가능)
    // 원하면 서버에서 JSON project list로 정제해서 반환하도록 바꿀 수도 있음.
    res.json({ ok: true, kriStatus: r.status, xml: xmlText });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ===== start =====
app.listen(PORT, () => {
  console.log(`kri-relay listening on ${PORT}`);
});
