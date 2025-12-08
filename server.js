// server.js (ESM)
// - /search 를 모바일(m.kri.go.kr) 대신 www IBSheet 엔드포인트(PG-RP-101-01js.jsp)로 전환
// - 모든 라우트 등록 후 app.listen()
// - port 선언 순서 수정
// - /search 응답: 원본 xml + (가능하면) rows JSON 파싱 결과 함께 반환

import express from "express";
import { CookieJar } from "tough-cookie";
import { fetch } from "undici";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---- Config (Render 환경변수로 주입) ----
const API_TOKEN = process.env.API_TOKEN;
const KRI_UID = process.env.KRI_UID;
const KRI_UPW = process.env.KRI_UPW;
const KRI_ID_B64 = process.env.KRI_ID_B64;
const KRI_PW_B64 = process.env.KRI_PW_B64;

if (!API_TOKEN || !KRI_UID || !KRI_UPW) {
  console.warn(
    "Missing env vars. Need API_TOKEN, KRI_UID, KRI_UPW (and ideally KRI_ID_B64/KRI_PW_B64)."
  );
}

// -------------------- auth --------------------
function auth(req, res, next) {
  const got = req.headers["x-api-token"];
  if (!API_TOKEN || got !== API_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// -------------------- cookie fetch client --------------------
function makeClient() {
  const jar = new CookieJar();

  async function cookieFetch(url, options = {}) {
    const u = new URL(url);
    const cookieHeader = await jar.getCookieString(u.origin + u.pathname);

    const headers = new Headers(options.headers || {});
    if (cookieHeader) headers.set("cookie", cookieHeader);

    const resp = await fetch(url, {
      ...options,
      headers,
      redirect: "manual"
    });

    const setCookies = resp.headers.getSetCookie?.() || [];
    for (const sc of setCookies) {
      await jar.setCookie(sc, url);
    }

    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get("location");
      if (loc) {
        const nextUrl = new URL(loc, url).toString();
        const nextOpts =
          resp.status === 303
            ? { method: "GET", headers: options.headers }
            : { ...options };
        return cookieFetch(nextUrl, nextOpts);
      }
    }

    return resp;
  }

  return { jar, cookieFetch };
}

// -------------------- login & warmup (www only) --------------------
async function kriLoginAndWarmup(cookieFetch) {
  // 1) init cookie
  await cookieFetch("https://www.kri.go.kr/kri2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
  });

  // 2) crosscert
  const form1 = new URLSearchParams();
  const idB64 = KRI_ID_B64 || Buffer.from(KRI_UID).toString("base64");
  const pwB64 = KRI_PW_B64 || Buffer.from(KRI_UPW).toString("base64");

  form1.set("id", idB64);
  form1.set("pw", pwB64);
  form1.set("loginCheck", "N");
  form1.set("sysid", "KRI");
  form1.set("skinColor", "sky_blue");
  form1.set("type", "10");
  form1.set("url", "https://www.kri.go.kr:443");
  form1.set("uid", KRI_UID);
  form1.set("upw", KRI_UPW);
  form1.set("mbr_dvs_Cd", "null");

  await cookieFetch(
    "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N",
    {
      method: "POST",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://www.kri.go.kr",
        Referer: "https://www.kri.go.kr/kri2"
      },
      body: form1.toString()
    }
  );

  // 3) login exec
  const q = new URLSearchParams();
  q.set("txtLoginId", idB64);
  q.set("txtLogDvs", "1");
  q.set("txtUserPw", pwB64);
  q.set("txtLoginDvs", "I");
  q.set("txtAnotherLogin", "N");
  q.set("txtAgree", "1");

  await cookieFetch(`https://www.kri.go.kr/kri/rp/login_exec.jsp?${q.toString()}`, {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      Referer:
        "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N"
    }
  });

  // 4) warm up list page + js (www)
  await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      Referer: "https://www.kri.go.kr/kri2"
    }
  });

  await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "X-Requested-With": "XMLHttpRequest",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: "https://www.kri.go.kr",
      Referer:
        "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2"
    },
    body: "requestOrder"
  });

  return { idB64, pwB64 };
}

// -------------------- parsing helpers --------------------
function parseRequestOrderCols(requestOrder) {
  // requestOrder 예: "|A|B|C"
  const raw = String(requestOrder || "");
  const cols = raw
    .split("|")
    .map((s) => s.trim())
    .filter(Boolean);
  return cols;
}

function parseIbsheetTrRows(xmlText, cols) {
  // 예시: <TR><![CDATA[‡11888822‡95‡...‡]]></TR>
  // 구분자 '‡'로 split. 앞/뒤 빈 칸이 있을 수 있어 filter로 정리.
  const xml = String(xmlText || "");
  const matches = [...xml.matchAll(/<TR>\s*<!\[CDATA\[(.*?)\]\]>\s*<\/TR>/gs)];

  const rows = [];
  for (const m of matches) {
    const cdata = m[1] ?? "";
    // split 후 첫 토큰이 비거나, 마지막이 비는 케이스 있음
    const parts = cdata.split("‡");
    const values = parts.filter((v) => v !== ""); // 가장 단순한 정리(필요시 조정)

    if (!cols?.length) {
      rows.push({ values });
      continue;
    }

    const obj = {};
    // cols 길이와 values 길이가 1:1이 아닐 수 있어 가능한 만큼만 매핑
    const n = Math.min(cols.length, values.length);
    for (let i = 0; i < n; i++) obj[cols[i]] = values[i];
    // 남는 값은 배열로 보관
    if (values.length > n) obj.__extra = values.slice(n);
    rows.push(obj);
  }
  return rows;
}

// -------------------- WWW search (replaces mobile search) --------------------
async function kriSearchWww({ name, pageNo = 1, pageSize = 500, userId = KRI_UID, requestOrder }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const ro =
    requestOrder ||
    "|RSCHR_REG_NO|BIRTH_DT|AGC_ID|MNG_NO|KOR_NM|SEX_DVS_CD|AGC_NM|SBJT_NM|POSI_NM|DGR_SPCL_CD|DGR_ACQS_AGC_CD|ACQS_DGR_DVS_CD|SBJT_CD|POSI_CD|INFO_OPEN_YN";

  const form = new URLSearchParams();
  form.set("requestOrder", ro);
  form.set("sheetAcation", "R");
  form.set("txtRschrRegNo", ""); // 검색 레지넘 지정 시 채움
  form.set("txtUser", String(userId ?? ""));
  form.set("txtMngNo", "");
  form.set("txtEngYn", "N");
  form.set("txtPUserDvs", "1");
  form.set("txtKorNm", name ?? "");
  form.set("txtKorHidden", "");
  form.set("txtAgcId", "");
  form.set("txtAgcNm", "");
  form.set("txtPosiCd", "");
  form.set("txtDgrSpclCd", "");
  form.set("txtLev", "");
  form.set("txtDgrSpclNm", "");
  form.set("txtDgrAcqsAgcCd", "");
  form.set("txtDgrAcqsAgcNm", "");
  form.set("txtSearchRschrRegNo", "");
  form.set("txtBirthDt", "");
  form.set("txtBirthDt2", "");
  form.set("ibTabTop0", "");
  form.set("editpage0", "");
  form.set("ibTabBottom0", "");
  form.set("ibTabTop1", "");
  form.set("editpage1", "");
  form.set("ibTabBottom1", "");
  form.set("iPageNo", String(pageNo));
  form.set("iPageSize", String(pageSize));

  const resp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: "https://www.kri.go.kr",
      Referer: "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2"
    },
    body: form.toString()
  });

  const xml = await resp.text();
  const cols = parseRequestOrderCols(ro);
  const rows = parseIbsheetTrRows(xml, cols);

  return { status: resp.status, xml, cols, rows };
}

// -------------------- existing single endpoints (www rschachv) --------------------
async function kriBasic({ rschrRegNo, name }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const url = new URL("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-102-02jr.jsp");
  url.searchParams.set("txtRschrRegNo", String(rschrRegNo));
  url.searchParams.set("txtKorNm", String(name));

  const body = new URLSearchParams();
  body.set("txtRschrRegNo", String(rschrRegNo));
  body.set("txtKorNm", String(name));

  const resp = await cookieFetch(url.toString(), {
    method: "POST",
    headers: {
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "max-age=0",
      Connection: "keep-alive",
      Origin: "https://www.kri.go.kr",
      "Upgrade-Insecure-Requests": "1",
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: body.toString()
  });

  return { status: resp.status, body: await resp.text() };
}

async function kriCareer({ rschrRegNo }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const form = new URLSearchParams();
  form.set(
    "requestOrder",
    "No.|RSCHR_REG_NO|MNG_NO|WORK_STT_YM|WORK_END_YM|WORK_AGC_NM|POSI_NM|CHG_BIZ_NM|MOD_DTTM|DEL_DVS_CD|REG_PE_ID|REG_DTTM|MOD_PE_ID|TRNSM_LOG_ID|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM||DATA_SRC_DVS_CD|BLNG_UNIV_CD|CHK"
  );
  form.set("sheetAcation", "F");
  form.set("txtRschrRegNo", String(rschrRegNo));

  const resp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-105-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr"
    },
    body: form.toString()
  });

  return { status: resp.status, body: await resp.text() };
}

async function kriAwards({ rschrRegNo }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const form = new URLSearchParams();
  form.set(
    "requestOrder",
    "|No|RSCHR_REG_NO|MNG_NO|AWRD_YM|AWRD_NM|AWRD_DVS_CD|CFMT_AGC_NM|CFMT_NTN_CD|APPR_DVS_CD|APPR_DTTM|BLNG_UNIV_CD|BLNG_UNIV_NM|REG_PE_ID|REG_DTTM|MOD_PE_ID|MOD_DTTM|DEL_DVS_CD|MDF_FOUN_DVS_CD|MDF_DVS_CD|MDF_RSLT_YN|REPL_DTTM|MDF_IP_NO|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|DATA_SRC_DVS_CD|BLNG_UNIV_CD"
  );
  form.set("sheetAcation", "R");
  form.set("txtRschrRegNo", String(rschrRegNo));

  const resp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-112-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr"
    },
    body: form.toString()
  });

  return { status: resp.status, body: await resp.text() };
}

async function kriPapers({ rschrRegNo }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const form = new URLSearchParams();
  form.set(
    "requestOrder",
    "|RSCHR_REG_NO|MNG_NO|PBLC_YM|LANG_PPR_NM|ORG_LANG_PPR_NM|DIFF_LANG_PPR_NM|KRF_REG_PBLC_YN|OVRS_EXCLNC_SCJNL_PBLC_YN|PBLC_NTN_CD|SCJNL_NM|PBLC_PLC_NM|ISSN_NO|PPR_LANG_DVS_CD|IMPCT_FCTR|SCJNL_DVS_CD|RSRCHACPS_STDY_SPHE_CD|SBJT_NO|TOTAL_ATHR_CNT|PBLC_VOL_NO|PBLC_BK_NO|STT_PAGE|END_PAGE|VRFC_DVS_CD|VRFC_DTTM|APPR_DVS_CD|APPR_DTTM|APPR_RTRN_CNCL_RSN_CNTN|BLNG_UNIV_NM|BLNG_UNIV_CD|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|RSRCHACPS_STDY_SPHE_NM|IRB_NO|MOD_DTTM|VRFC_PE_ID|APPR_PE_ID|VRFC_PE_NM|SBJT_NM|ABST_CNTN|LOGIC_FILE_NM|PHYSIC_FILE_NM| |VRFC_PPR_ID|VRFC_SRC_DVS_CD|DATA_SRC_DVS_CD|SCI_DVS_CD|OVERLAP_CHK|DOI"
  );
  form.set("sheetAcation", "F");
  form.set("txtRschrRegNo", String(rschrRegNo));

  const resp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-108-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr"
    },
    body: form.toString()
  });

  return { status: resp.status, body: await resp.text() };
}

async function kriFunding({ rschrRegNo }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  const form = new URLSearchParams();
  form.set(
    "requestOrder",
    "|RSCHR_REG_NO|MNG_NO|RSCH_CMCM_YM|RSCH_END_YM|RSRCCT_SPPT_DVS_CD|RSCH_SBJT_STDY_SPHE_CD|RSCH_SBJT_NM|RSRCCT_SPPT_AGC_NM|TOT_RSRCCT|SBJT_NO|MNY_YR_SBJT_YN|BIZ_NM|CPT_GOV_OFFIC_NM|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|MOD_DTTM|APPR_DVS_CD|APPR_RTRN_CNCL_RSN_CNTN|APPR_DTTM|DATA_SRC_DVS_CD|VRFC_DVS_CD|VRFC_DTTM|VRFC_PE_ID|VRFC_PE_NM|BLNG_UNIV_CD"
  );
  form.set("sheetAcation", "F");
  form.set("txtRschrRegNo", String(rschrRegNo));

  const resp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-110-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr"
    },
    body: form.toString()
  });

  return { status: resp.status, body: await resp.text() };
}

// -------------------- routes --------------------
app.get("/health", (req, res) => res.json({ ok: true }));

// ✅ 검색 API (www IBSheet 기반)
// body: { name, pageNo?, pageSize?, requestOrder? }
// - rows: requestOrder 컬럼명으로 매핑된 JSON
// - xml: 원문 XML
app.post("/search", auth, async (req, res) => {
  try {
    const { name, pageNo, pageSize, requestOrder } = req.body || {};
    if (!name) {
      return res.status(400).json({ ok: false, error: "name is required" });
    }

    const t0 = Date.now();
    const out = await kriSearchWww({
      name,
      pageNo: pageNo ?? 1,
      pageSize: pageSize ?? 100,
      requestOrder
    });
    const ms = Date.now() - t0;

    res.json({
      ok: true,
      tookMs: ms,
      kriStatus: out.status,
      cols: out.cols,
      rows: out.rows,
      xml: out.xml
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

app.post("/basic", auth, async (req, res) => {
  try {
    const { rschrRegNo, name } = req.body || {};
    if (!rschrRegNo || !name) {
      return res.status(400).json({ ok: false, error: "rschrRegNo and name are required" });
    }
    const t0 = Date.now();
    const out = await kriBasic({ rschrRegNo, name });
    res.json({ ok: true, tookMs: Date.now() - t0, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

app.post("/career", auth, async (req, res) => {
  try {
    const { rschrRegNo } = req.body || {};
    if (!rschrRegNo) {
      return res.status(400).json({ ok: false, error: "rschrRegNo is required" });
    }
    const t0 = Date.now();
    const out = await kriCareer({ rschrRegNo });
    res.json({ ok: true, tookMs: Date.now() - t0, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

app.post("/awards", auth, async (req, res) => {
  try {
    const { rschrRegNo } = req.body || {};
    if (!rschrRegNo) {
      return res.status(400).json({ ok: false, error: "rschrRegNo is required" });
    }
    const t0 = Date.now();
    const out = await kriAwards({ rschrRegNo });
    res.json({ ok: true, tookMs: Date.now() - t0, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

app.post("/papers", auth, async (req, res) => {
  try {
    const { rschrRegNo } = req.body || {};
    if (!rschrRegNo) {
      return res.status(400).json({ ok: false, error: "rschrRegNo is required" });
    }
    const t0 = Date.now();
    const out = await kriPapers({ rschrRegNo });
    res.json({ ok: true, tookMs: Date.now() - t0, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

app.post("/funding", auth, async (req, res) => {
  try {
    const { rschrRegNo } = req.body || {};
    if (!rschrRegNo) {
      return res.status(400).json({ ok: false, error: "rschrRegNo is required" });
    }
    const t0 = Date.now();
    const out = await kriFunding({ rschrRegNo });
    res.json({ ok: true, tookMs: Date.now() - t0, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

// -------------------- listen --------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`kri-relay listening on ${port}`));
