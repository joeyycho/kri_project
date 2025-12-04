// server.js
// 국가연구자번호로 KRI(한국연구업적통합정보)에서 논문/프로젝트 데이터를 가져오는 릴레이 서버
import express from "express";
import { CookieJar } from "tough-cookie";
import { fetch } from "undici";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ===== 환경변수 =====
const API_TOKEN = process.env.API_TOKEN || "";
const KRI_ID_B64 = process.env.KRI_ID_B64 || ""; // txtLoginId / id 에 들어가는 base64 아이디
const KRI_PW_B64 = process.env.KRI_PW_B64 || ""; // txtUserPw / pw 에 들어가는 base64 비밀번호
const KRI_UID = process.env.KRI_UID || "";       // uid 필드용 (평문 아이디) - 없으면 ID_B64 디코딩해서 사용
const KRI_UPW = process.env.KRI_UPW || "";       // upw 필드용 (평문 비번) - 없으면 PW_B64 디코딩해서 사용
const PORT = process.env.PORT || 3000;

if (!API_TOKEN) {
  console.warn("⚠️ 환경변수 API_TOKEN 이 설정되지 않았습니다. (x-api-token 헤더 인증에 사용)");
}
if (!KRI_ID_B64 || !KRI_PW_B64) {
  console.warn("⚠️ 환경변수 KRI_ID_B64 / KRI_PW_B64 가 설정되지 않았습니다. KRI 로그인에 필요합니다.");
}

// base64 아이디/비밀번호를 평문으로 디코딩 (uid/upw 에 사용)
function safeBase64Decode(s) {
  if (!s) return "";
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}

const LOGIN_ID_B64 = KRI_ID_B64;
const LOGIN_PW_B64 = KRI_PW_B64;
const LOGIN_UID = KRI_UID || safeBase64Decode(LOGIN_ID_B64);
const LOGIN_UPW = KRI_UPW || safeBase64Decode(LOGIN_PW_B64);

// ===== 간단 인증 미들웨어 =====
function auth(req, res, next) {
  const got = req.headers["x-api-token"];
  if (!API_TOKEN || got !== API_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// ===== CookieJar + fetch 래퍼 =====
function makeClient() {
  const jar = new CookieJar();

  async function cookieFetch(url, options = {}) {
    const u = new URL(url);
    const cookieHeader = await jar.getCookieString(u.origin + u.pathname);

    const headers = new Headers(options.headers || {});
    if (cookieHeader && !headers.has("cookie")) {
      headers.set("cookie", cookieHeader);
    }

    const resp = await fetch(url, {
      ...options,
      headers,
      redirect: "manual", // 우리가 직접 리다이렉트 따라감
    });

    // Set-Cookie 저장
    const setCookies = resp.headers.getSetCookie?.() || [];
    for (const sc of setCookies) {
      await jar.setCookie(sc, url);
    }

    // 30x 리다이렉트 수동 처리
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

// ===== KRI 로그인 플로우 (n8n Cookie 플로우 이식) =====
async function kriLogin(client) {
  const { jar, cookieFetch } = client;

  if (!LOGIN_ID_B64 || !LOGIN_PW_B64) {
    throw new Error("KRI_ID_B64 / KRI_PW_B64 환경변수가 설정되지 않아 로그인할 수 없습니다.");
  }

  // 1) 메인 페이지로 진입해서 기본 쿠키(WMONID, JSESSIONID 등) 확보
  await cookieFetch("https://www.kri.go.kr/kri2", {
    method: "GET",
    headers: {
      Host: "www.kri.go.kr",
      Connection: "keep-alive",
      "Cache-Control": "max-age=0",
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-User": "?1",
      "Sec-Fetch-Dest": "document",
      Referer: "https://www.kri.go.kr/kri2",
    },
  });

  // 2) crosscert/GetCertSign.jsp 로 POST (id/pw, uid/upw 등)
  const certForm = new URLSearchParams();
  certForm.set("id", LOGIN_ID_B64);
  certForm.set("pw", LOGIN_PW_B64);
  certForm.set("loginCheck", "N");
  certForm.set("sysid", "KRI");
  certForm.set("urlRealPath", "");
  certForm.set("txtAgcId", "");
  certForm.set("skinColor", "sky_blue");
  certForm.set("nexturl", "");
  certForm.set("type", "10");
  certForm.set("turl", "");
  certForm.set("afterjs", "");
  certForm.set("ntarget", "");
  certForm.set("sUrl", "");
  certForm.set("url", "https://www.kri.go.kr:443");
  certForm.set("loginGbn", "");
  certForm.set("txtGbn", "");
  certForm.set("kriAthidSi", "");
  certForm.set("krimsAthNo", "");
  certForm.set("tmpMbrDvsCd", "");
  certForm.set("uid", LOGIN_UID || "");
  certForm.set("upw", LOGIN_UPW || "");
  certForm.set("mbr_dvs_Cd", "null");

  const certResp = await cookieFetch(
    "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N",
    {
      method: "POST",
      headers: {
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "max-age=0",
        Connection: "keep-alive",
        Origin: "https://www.kri.go.kr",
        Referer: "https://www.kri.go.kr/kri2",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec-ch-ua":
          '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: certForm.toString(),
    }
  );
  const certText = await certResp.text();

  if (certText.includes("로그인 시간이 초과되었습니다")) {
    throw new Error("KRI GetCertSign 단계에서 로그인 시간이 초과되었습니다.");
  }

  // 3) login_exec.jsp 로 GET (base64 ID/PW 사용)
  const loginParams = new URLSearchParams({
    txtLoginId: LOGIN_ID_B64,
    txtLogDvs: "1",
    txtUserPw: LOGIN_PW_B64,
    txtLoginDvs: "I",
    txtAnotherLogin: "N",
    txtAgree: "1",
  });

  const loginResp = await cookieFetch(
    "https://www.kri.go.kr/kri/rp/login_exec.jsp?" + loginParams.toString(),
    {
      method: "GET",
      headers: {
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        Connection: "keep-alive",
        Referer:
          "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec-ch-ua":
          '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
      },
    }
  );
  const loginText = await loginResp.text();
  if (
    loginText.includes("로그인 시간이 초과되었습니다") ||
    loginText.includes("로그인에 실패")
  ) {
    throw new Error("KRI 로그인에 실패했습니다.");
  }

  // 4) potalHelpViewYn=Y 쿠키 설정 + 업적 페이지 진입 (PG-RP-101-01jl.jsp)
  await jar.setCookie("potalHelpViewYn=Y; Domain=www.kri.go.kr; Path=/;", "https://www.kri.go.kr/");

  const rschPageResp = await cookieFetch(
    "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2",
    {
      method: "GET",
      headers: {
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        Connection: "keep-alive",
        Referer: "https://www.kri.go.kr/kri2",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec-ch-ua":
          '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
      },
    }
  );
  const rschText = await rschPageResp.text();
  if (rschText.includes("로그인 시간이 초과되었습니다")) {
    throw new Error("KRI 업적 페이지 진입 중 세션이 만료되었습니다.");
  }
}

// ===== 논문/프로젝트 조회 (108 / 110 JSP) =====
async function kriFetchByResearcherNo(researcherId) {
  const client = makeClient();
  const { cookieFetch } = client;

  // 1) 로그인 및 업적 페이지 세션 확보
  await kriLogin(client);

  const commonAjaxHeaders = {
    "User-Agent":
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    Origin: "https://www.kri.go.kr",
    Referer:
      "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2",
    Connection: "keep-alive",
  };

  // 2) 논문(108) 조회
  const paperForm = new URLSearchParams();
  paperForm.set(
    "requestOrder",
    "=|RSCHR_REG_NO|MNG_NO|PBLC_YM|LANG_PPR_NM|ORG_LANG_PPR_NM|DIFF_LANG_PPR_NM|KRF_REG_PBLC_YN|OVRS_EXCLNC_SCJNL_PBLC_YN|PBLC_NTN_CD|SCJNL_NM|PBLC_PLC_NM|ISSN_NO|PPR_LANG_DVS_CD|IMPCT_FCTR|SCJNL_DVS_CD|RSRCHACPS_STDY_SPHE_CD|SBJT_NO|TOTAL_ATHR_CNT|PBLC_VOL_NO|PBLC_BK_NO|STT_PAGE|END_PAGE|VRFC_DVS_CD|VRFC_DTTM|APPR_DVS_CD|APPR_DTTM|APPR_RTRN_CNCL_RSN_CNTN|BLNG_UNIV_NM|BLNG_UNIV_CD|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|RSRCHACPS_STDY_SPHE_NM|IRB_NO|MOD_DTTM|VRFC_PE_ID|APPR_PE_ID|VRFC_PE_NM|SBJT_NM|ABST_CNTN|LOGIC_FILE_NM|PHYSIC_FILE_NM| |VRFC_PPR_ID|VRFC_SRC_DVS_CD|DATA_SRC_DVS_CD|SCI_DVS_CD|OVERLAP_CHK|DOI"
  );
  paperForm.set("sheetAcation", "F");
  paperForm.set("txtRschrRegNo", String(researcherId));

  const paperResp = await cookieFetch(
    "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-108-01js.jsp",
    {
      method: "POST",
      headers: commonAjaxHeaders,
      body: paperForm.toString(),
    }
  );
  const paperText = await paperResp.text();
  let paperJson = null;
  try {
    paperJson = JSON.parse(paperText);
  } catch {
    paperJson = null;
  }

  // 3) 프로젝트/연구비(110) 조회
  const projForm = new URLSearchParams();
  projForm.set(
    "requestOrder",
    "=|RSCHR_REG_NO|MNG_NO|RSCH_CMCM_YM|RSCH_END_YM|RSRCCT_SPPT_DVS_CD|RSCH_SBJT_STDY_SPHE_CD|RSCH_SBJT_NM|RSRCCT_SPPT_AGC_NM|TOT_RSRCCT|SBJT_NO|MNY_YR_SBJT_YN|BIZ_NM|CPT_GOV_OFFIC_NM|APD01_FLD_NM|APD02_FLD_NM|APD03_FLD_NM|APD04_FLD_NM|APD05_FLD_NM|MOD_DTTM|APPR_DVS_CD|APPR_RTRN_CNCL_RSN_CNTN|APPR_DTTM|DATA_SRC_DVS_CD|VRFC_DVS_CD|VRFC_DTTM|VRFC_PE_ID|VRFC_PE_NM|BLNG_UNIV_CD"
  );
  projForm.set("sheetAcation", "F");
  projForm.set("txtRschrRegNo", String(researcherId));

  const projResp = await cookieFetch(
    "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-110-01js.jsp",
    {
      method: "POST",
      headers: commonAjaxHeaders,
      body: projForm.toString(),
    }
  );
  const projText = await projResp.text();
  let projJson = null;
  try {
    projJson = JSON.parse(projText);
  } catch {
    projJson = null;
  }

  return {
    papers: {
      status: paperResp.status,
      contentType: paperResp.headers.get("content-type") || null,
      raw: paperText,
      json: paperJson,
    },
    projects: {
      status: projResp.status,
      contentType: projResp.headers.get("content-type") || null,
      raw: projText,
      json: projJson,
    },
  };
}

// ===== 헬스 체크 =====
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// ===== 메인 API: 국가연구자번호로 논문 + 프로젝트 조회 =====
// POST /kri/by-id
// Body: { "researcherId": "12570694" }
// Header: x-api-token: <API_TOKEN>
app.post("/kri/by-id", auth, async (req, res) => {
  try {
    const { researcherId } = req.body || {};
    if (!researcherId) {
      return res.status(400).json({
        ok: false,
        error: "researcherId (국가연구자번호) is required",
      });
    }

    const t0 = Date.now();
    const out = await kriFetchByResearcherNo(researcherId);
    const ms = Date.now() - t0;

    res.json({
      ok: true,
      tookMs: ms,
      researcherId,
      papers: out.papers,    // { status, contentType, raw, json }
      projects: out.projects // { status, contentType, raw, json }
    });
  } catch (e) {
    console.error("KRI relay error:", e);
    res.status(500).json({
      ok: false,
      error: e?.message || "Unknown error",
    });
  }
});

app.listen(PORT, () => {
  console.log(`kri-relay listening on port ${PORT}`);
});
