import express from "express";
import { CookieJar } from "tough-cookie";
import { fetch } from "undici";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---- Config (Render 환경변수로 주입) ----
const API_TOKEN = process.env.API_TOKEN; // 릴레이 호출 인증 토큰
const KRI_UID = process.env.KRI_UID;     // 예: koolee33
const KRI_UPW = process.env.KRI_UPW;     // 예: c2W97CH5~Z6m&L

// 기존 n8n에 있던 base64 값(있으면 그대로 환경변수로 넣고 사용)
const KRI_ID_B64 = process.env.KRI_ID_B64; // 예: a29vbGVlMzM=
const KRI_PW_B64 = process.env.KRI_PW_B64; // 예: YzJXOTdDSDV+WjZtJkw=

if (!API_TOKEN || !KRI_UID || !KRI_UPW) {
  console.warn(
    "Missing env vars. Need API_TOKEN, KRI_UID, KRI_UPW (and ideally KRI_ID_B64/KRI_PW_B64)."
  );
}

// 간단 인증 미들웨어
function auth(req, res, next) {
  const got = req.headers["x-api-token"];
  if (!API_TOKEN || got !== API_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// 쿠키jar + fetch wrapper
function makeClient() {
  const jar = new CookieJar();

  async function cookieFetch(url, options = {}) {
    const u = new URL(url);
    // tough-cookie는 domain/path 기준이라 origin+pathname로 충분
    const cookieHeader = await jar.getCookieString(u.origin + u.pathname);

    const headers = new Headers(options.headers || {});
    if (cookieHeader) headers.set("cookie", cookieHeader);

    const resp = await fetch(url, {
      ...options,
      headers,
      redirect: "manual"
    });

    // Set-Cookie 저장
    const setCookies = resp.headers.getSetCookie?.() || [];
    for (const sc of setCookies) {
      await jar.setCookie(sc, url);
    }

    // 30x 리다이렉트 따라가기(필요시)
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

/**
 * KRI 로그인 + (옵션)모바일 검색까지 1회 세션으로 수행
 */
async function kriLoginAndWarmup(cookieFetch) {
  // 1) Get Cookie
  await cookieFetch("https://www.kri.go.kr/kri2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
  });

  // 2) GetCertSign.jsp (POST)
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

  await cookieFetch("https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr",
      Referer: "https://www.kri.go.kr/kri2"
    },
    body: form1.toString()
  });

  // 3) login_exec.jsp (GET with query)
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

  // 4) 워밍업
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

  // 4.5) 모바일 도메인 쿠키/세션 확보
  await cookieFetch("https://m.kri.go.kr/kri/mobile/KRI_RP_MO_001.jsp", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
      Referer: "https://m.kri.go.kr/"
    }
  });

  return { idB64, pwB64 };
}

async function kriSearch({ name, org }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  // 5) 모바일 검색 POST
  const form2 = new URLSearchParams();
  form2.set("mode", "firstSearch");
  form2.set("txtSchNm", name ?? "");
  form2.set("txtAgcNmP", org ?? "");

  const resp = await cookieFetch("https://m.kri.go.kr/kri/mobile/PG-RP-101-01jl.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://m.kri.go.kr",
      Referer: "https://m.kri.go.kr/kri/mobile/KRI_RP_MO_001.jsp",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"
    },
    body: form2.toString()
  });

  const html = await resp.text();
  return { status: resp.status, html };
}

/**
 * ✅ 추가: 기본정보/경력사항/수상사항 호출
 * - n8n에서 하던 3개 HTTP Request를 Node에서 같은 세션(cookie jar)로 실행
 */
async function kriFetchDetails({ rschrRegNo, name }) {
  const { cookieFetch } = makeClient();
  await kriLoginAndWarmup(cookieFetch);

  // 1) 기본정보 (PG-RP-102-02jr.jsp)
  const basicUrl = new URL("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-102-02jr.jsp");
  basicUrl.searchParams.set("txtRschrRegNo", String(rschrRegNo));
  basicUrl.searchParams.set("txtKorNm", String(name));

  const basicForm = new URLSearchParams();
  basicForm.set("txtRschrRegNo", String(rschrRegNo));
  basicForm.set("txtKorNm", String(name));

  const basicResp = await cookieFetch(basicUrl.toString(), {
    method: "POST",
    headers: {
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "max-age=0",
      Connection: "keep-alive",
      Origin: "https://www.kri.go.kr",
      "Sec-Fetch-Dest": "iframe",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-User": "?1",
      "Upgrade-Insecure-Requests": "1",
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "sec-ch-ua": "\"Google Chrome\";v=\"129\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"129\"",
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": "\"macOS\"",
      "Content-Type": "application/x-www-form-urlencoded"
      // cookie 헤더는 jar에서 자동으로 붙음
    },
    body: basicForm.toString()
  });

  const basicHtml = await basicResp.text();

  // 2) 경력사항 (PG-RP-105-01js.jsp)
  const careerForm = new URLSearchParams();
  careerForm.set(
    "requestOrder",
    "No.|RSCHR_REG_NO|MNG_NO|WORK_STT_YM|WORK_END_YM|WORK_AGC_NM|POSI_NM|CHG_BIZ_NM|MOD_DTTM|DEL_DVS_CD|REG_PE_ID|REG_DTTM|MOD_PE_ID|TRNSM_LOG_ID|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM||DATA_SRC_DVS_CD|BLNG_UNIV_CD|CHK"
  );
  careerForm.set("sheetAcation", "F");
  careerForm.set("txtRschrRegNo", String(rschrRegNo));

  const careerResp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-105-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr",
      Referer: "https://www.kri.go.kr/kri2"
    },
    body: careerForm.toString()
  });
  const careerText = await careerResp.text();

  // 3) 수상사항 (PG-RP-112-01js.jsp)
  const awardForm = new URLSearchParams();
  awardForm.set(
    "requestOrder",
    "|No|RSCHR_REG_NO|MNG_NO|AWRD_YM|AWRD_NM|AWRD_DVS_CD|CFMT_AGC_NM|CFMT_NTN_CD|APPR_DVS_CD|APPR_DTTM|BLNG_UNIV_CD|BLNG_UNIV_NM|REG_PE_ID|REG_DTTM|MOD_PE_ID|MOD_DTTM|DEL_DVS_CD|MDF_FOUN_DVS_CD|MDF_DVS_CD|MDF_RSLT_YN|REPL_DTTM|MDF_IP_NO|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|DATA_SRC_DVS_CD|BLNG_UNIV_CD"
  );
  awardForm.set("sheetAcation", "R");
  awardForm.set("txtRschrRegNo", String(rschrRegNo));

  const awardResp = await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-112-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://www.kri.go.kr",
      Referer: "https://www.kri.go.kr/kri2"
    },
    body: awardForm.toString()
  });
  const awardText = await awardResp.text();

  return {
    basic: { status: basicResp.status, body: basicHtml },
    career: { status: careerResp.status, body: careerText },
    awards: { status: awardResp.status, body: awardText }
  };
}

// 헬스체크
app.get("/health", (req, res) => res.json({ ok: true }));

// 검색 API (기존)
app.post("/search", auth, async (req, res) => {
  try {
    const { name, org } = req.body || {};
    if (!name || !org) {
      return res.status(400).json({ ok: false, error: "name and org are required" });
    }

    const t0 = Date.now();
    const out = await kriSearch({ name, org });
    const ms = Date.now() - t0;

    res.json({
      ok: true,
      tookMs: ms,
      kriStatus: out.status,
      html: out.html
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

// ✅ 추가: 상세(기본정보/경력/수상) API
app.post("/detail", auth, async (req, res) => {
  try {
    const { rschrRegNo, name } = req.body || {};
    if (!rschrRegNo || !name) {
      return res.status(400).json({ ok: false, error: "rschrRegNo and name are required" });
    }

    const t0 = Date.now();
    const out = await kriFetchDetails({ rschrRegNo, name });
    const ms = Date.now() - t0;

    res.json({
      ok: true,
      tookMs: ms,
      rschrRegNo,
      name,
      sections: out
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || "Unknown error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`kri-relay listening on ${port}`));
