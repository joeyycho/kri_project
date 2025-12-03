// server.js
import express from "express";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ====== ENV ======
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.API_TOKEN; // n8n에서 X-API-Token으로 보낼 토큰

const KRI_UID = process.env.KRI_UID; // KRI 아이디 (plain)
const KRI_UPW = process.env.KRI_UPW; // KRI 비번 (plain)

const KRI_ID_B64 = process.env.KRI_ID_B64; // optional
const KRI_PW_B64 = process.env.KRI_PW_B64; // optional

if (!API_TOKEN) console.warn("Missing API_TOKEN env");
if (!KRI_UID || !KRI_UPW) console.warn("Missing KRI_UID or KRI_UPW env");

// ====== Simple Auth ======
function auth(req, res, next) {
  const token = req.header("X-API-Token");
  if (!token || token !== API_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// ====== In-memory cookie jar ======
let jar = {
  wmonid: null,
  jsessionid: null,
  lastLoginAt: 0,
};

const LOGIN_TTL_MS = 1000 * 60 * 10; // 10분 (적당히 늘리거나 줄이세요)

// ====== helpers ======
const now = () => Date.now();

function safeStr(v) {
  return String(v ?? "").trim();
}

function cookieHeader() {
  const parts = [];
  if (jar.wmonid) parts.push(`WMONID=${jar.wmonid}`);
  if (jar.jsessionid) parts.push(`JSESSIONID=${jar.jsessionid}`);
  return parts.join("; ");
}

/**
 * Node/undici/express 환경별로 set-cookie 가져오는 방법이 달라서 최대한 방어적으로 처리
 */
function getSetCookieArray(res) {
  // 1) Node 20+ 일부 환경: getSetCookie()
  if (res?.headers?.getSetCookie) {
    try {
      const v = res.headers.getSetCookie();
      if (Array.isArray(v)) return v;
    } catch {}
  }

  // 2) undici Headers: set-cookie 단일 문자열(합쳐진 경우가 있어 split 위험)
  //    일단 하나로라도 받으면 배열로 감싼다.
  const sc = res?.headers?.get?.("set-cookie");
  if (sc) return Array.isArray(sc) ? sc : [sc];

  // 3) node-fetch 스타일 raw()
  if (res?.headers?.raw) {
    try {
      const raw = res.headers.raw();
      if (raw?.["set-cookie"]) return raw["set-cookie"];
    } catch {}
  }

  return [];
}

function parseSetCookie(setCookieArr = []) {
  // set-cookie: ["WMONID=...; Path=/; ...", "JSESSIONID=...; Path=/; ...", ...]
  const out = {};
  for (const c of setCookieArr) {
    const first = String(c).split(";")[0];
    const idx = first.indexOf("=");
    if (idx === -1) continue;
    const k = first.slice(0, idx).trim();
    const v = first.slice(idx + 1).trim();
    if (k && v) out[k] = v;
  }
  return out;
}

async function fetchFull(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  return { res, text };
}

// ====== KRI login flow ======
async function ensureLogin() {
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

    const setCookie = getSetCookieArray(res);
    const parsed = parseSetCookie(setCookie);

    if (parsed.WMONID) jar.wmonid = parsed.WMONID;
    if (parsed.JSESSIONID) jar.jsessionid = parsed.JSESSIONID;
  }

  if (!jar.jsessionid) throw new Error("Failed to obtain JSESSIONID from KRI");

  // 2) CrossCert step
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

  // 4) 검색 페이지 진입 + requestOrder (세션 안정화)
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

// ====== KRI XML 응답(TR) → JSON 배열 파서 ======
// KRI는 <TR>마다 "‡" 구분자 문자열을 내려줍니다.
// 첫 칼럼이 보통 row index 같은 값이라, 기존 Code23처럼 idx+1로 맞춥니다.
function parseKriSheetToJson(xmlText, requestOrder) {
  const cols = requestOrder.split("|").filter(Boolean);

  // <TR>...</TR> 문자열 추출 (간단 파싱: XML parser 없이)
  const trMatches = xmlText.match(/<TR>([\s\S]*?)<\/TR>/gi) || [];

  const rows = [];

  for (const tr of trMatches) {
    // TR 내부 텍스트만 뽑기 (태그 제거)
    const inner = tr
      .replace(/^<TR>/i, "")
      .replace(/<\/TR>$/i, "")
      .replace(/<[^>]+>/g, "") // 혹시 태그가 섞이면 제거
      .trim();

    if (!inner) continue;

    const parts = inner.split("‡");

    // 기존 Code23로 미루어보면 parts[0]은 의미 없는 값(행 번호/구분)일 가능성이 높아 idx+1 사용
    const obj = {};
    cols.forEach((key, idx) => {
      obj[key] = (parts[idx + 1] ?? "").trim();
    });

    // “빈 행” 방지: 전부 빈 문자열이면 skip
    const hasAny = Object.values(obj).some((v) => v !== "");
    if (hasAny) rows.push(obj);
  }

  return rows;
}

// 공통: 특정 엔드포인트 호출 → JSON 배열 반환
async function kriFetchSheetAsJson({ kri_id, url, requestOrder }) {
  await ensureLogin();

  const body = new URLSearchParams({
    requestOrder,
    sheetAcation: "F",
    txtRschrRegNo: kri_id,
  }).toString();

  const { res: r, text: xmlText } = await fetchFull(url, {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": `JSESSIONID=${jar.jsessionid}`,
    },
    body,
  });

  const data = parseKriSheetToJson(xmlText, requestOrder);

  return { kriStatus: r.status, data };
}

// ====== Routes ======
app.get("/health", (req, res) => res.json({ ok: true }));

// (1) 이름/소속으로 KRI 모바일 검색 HTML 반환
app.post("/search", auth, async (req, res) => {
  try {
    const name = safeStr(req.body?.name);
    const org = safeStr(req.body?.org);

    await ensureLogin();

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

// (2) Projects
app.post("/projects", auth, async (req, res) => {
  try {
    const kri_id = safeStr(req.body?.kri_id);
    if (!kri_id) return res.status(400).json({ ok: false, error: "Missing kri_id" });

    // ✅ 사용자가 준 프로젝트 requestOrder (그대로)
    const requestOrder =
      "|RSCHR_REG_NO|MNG_NO|RSCH_CMCM_YM|RSCH_END_YM|RSRCCT_SPPT_DVS_CD|RSCH_SBJT_STDY_SPHE_CD|RSCH_SBJT_NM|RSRCCT_SPPT_AGC_NM|TOT_RSRCCT|SBJT_NO|MNY_YR_SBJT_YN|BIZ_NM|CPT_GOV_OFFIC_NM|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|MOD_DTTM|APPR_DVS_CD|APPR_RTRN_CNCL_RSN_CNTN|APPR_DTTM|DATA_SRC_DVS_CD|VRFC_DVS_CD|VRFC_DTTM|VRFC_PE_ID|VRFC_PE_NM|BLNG_UNIV_CD";

    const { kriStatus, data } = await kriFetchSheetAsJson({
      kri_id,
      url: "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-110-01js.jsp",
      requestOrder,
    });

    res.json({ ok: true, kriStatus, data });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// (3) Papers
app.post("/papers", auth, async (req, res) => {
  try {
    const kri_id = safeStr(req.body?.kri_id);
    if (!kri_id) return res.status(400).json({ ok: false, error: "Missing kri_id" });

    const requestOrder =
      "|RSCHR_REG_NO|MNG_NO|PBLC_YM|LANG_PPR_NM|ORG_LANG_PPR_NM|DIFF_LANG_PPR_NM|KRF_REG_PBLC_YN|OVRS_EXCLNC_SCJNL_PBLC_YN|PBLC_NTN_CD|SCJNL_NM|PBLC_PLC_NM|ISSN_NO|PPR_LANG_DVS_CD|IMPCT_FCTR|SCJNL_DVS_CD|RSRCHACPS_STDY_SPHE_CD|SBJT_NO|TOTAL_ATHR_CNT|PBLC_VOL_NO|PBLC_BK_NO|STT_PAGE|END_PAGE|VRFC_DVS_CD|VRFC_DTTM|APPR_DVS_CD|APPR_DTTM|APPR_RTRN_CNCL_RSN_CNTN|BLNG_UNIV_NM|BLNG_UNIV_CD|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|RSRCHACPS_STDY_SPHE_NM|IRB_NO|MOD_DTTM|VRFC_PE_ID|APPR_PE_ID|VRFC_PE_NM|SBJT_NM|ABST_CNTN|LOGIC_FILE_NM|PHYSIC_FILE_NM| |VRFC_PPR_ID|VRFC_SRC_DVS_CD|DATA_SRC_DVS_CD|SCI_DVS_CD|OVERLAP_CHK|DOI";

    const { kriStatus, data } = await kriFetchSheetAsJson({
      kri_id,
      url: "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-108-01js.jsp",
      requestOrder,
    });

    res.json({ ok: true, kriStatus, data });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// (4) Patents / IP
app.post("/patents", auth, async (req, res) => {
  try {
    const kri_id = safeStr(req.body?.kri_id);
    if (!kri_id) return res.status(400).json({ ok: false, error: "Missing kri_id" });

    const requestOrder =
      "|RSCHR_REG_NO|MNG_NO|ITL_PPR_RGT_DVS_CD|ACQS_DVS_CD|ITL_PPR_RGT_NM|ACQS_NTN_DVS_CD|ACQS_DTL_DVS_CD|APPL_REG_NTN_CD|APPL_REG_NO|APPL_REG_DATE|INVT_NM|SMMR_CNTN|SBJT_NO|PCT_EPO_APPL_NTN_CNT|INVT_CNT|APPL_REGT_NM|BLNG_UNIV_CD|APPR_CNCL_DTTM|APPR_RTRN_CNCL_RSN_CNTN|VRFC_DVS_CD|AUTO_VRFC_DVS_CD|VRFC_DTTM|AUTO_VRFC_DTTM|APPR_DVS_CD|APPR_DTTM|BLNG_UNIV_NM|DEL_DVS_CD|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|MOD_DTTM|VRFC_PE_ID|PAT_CLS_CD|VRFC_PE_NM|SBJT_NM|DATA_SRC_DVS_CD|ITL_PPR_RGT_REG_NO|ITL_PPR_RGT_REG_DATE|OVERLAP_CHK";

    const { kriStatus, data } = await kriFetchSheetAsJson({
      kri_id,
      url: "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-106-01js.jsp",
      requestOrder,
    });

    res.json({ ok: true, kriStatus, data });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ===== start =====
app.listen(PORT, () => {
  console.log(`kri-relay listening on ${PORT}`);
});
