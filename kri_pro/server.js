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
  console.warn("Missing env vars. Need API_TOKEN, KRI_UID, KRI_UPW (and ideally KRI_ID_B64/KRI_PW_B64).");
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
    const cookieHeader = await jar.getCookieString(u.origin + u.pathname);

    const headers = new Headers(options.headers || {});
    if (cookieHeader) headers.set("cookie", cookieHeader);

    const resp = await fetch(url, {
      ...options,
      headers,
      redirect: "manual" // 쿠키 직접 따라가므로 manual 유지
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
        // 303이면 GET으로 변경하는게 일반적
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
 * KRI 로그인 + 모바일 검색까지 1회 세션으로 수행
 */
async function kriSearch({ name, org }) {
  const { cookieFetch } = makeClient();

  // 1) Get Cookie
  await cookieFetch("https://www.kri.go.kr/kri2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
  });

  // 2) GetCertSign.jsp (POST)
  // n8n 원본 바디 기반(필요한 것만)
  const form1 = new URLSearchParams();
  // base64 값이 있으면 그대로 쓰고, 없으면 uid/upw를 base64로 만들어서 사용(원본과 다를 수 있어 권장X)
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
      "Origin": "https://www.kri.go.kr",
      "Referer": "https://www.kri.go.kr/kri2"
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
      "Referer": "https://www.kri.go.kr/kri/rp/crosscert/GetCertSign.jsp?txtAnotherLogin=N"
    }
  });

  // 4) (선택) 페이지 워밍업 (너 원본 플로우와 유사)
  await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Referer": "https://www.kri.go.kr/kri2"
    }
  });

  await cookieFetch("https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01js.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "X-Requested-With": "XMLHttpRequest",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "Origin": "https://www.kri.go.kr",
      "Referer": "https://www.kri.go.kr/kri/rp/rschachv/PG-RP-101-01jl.jsp?new=new2"
    },
    body: "requestOrder"
  });

  // 5) 모바일 검색 POST
  const form2 = new URLSearchParams();
  form2.set("mode", "firstSearch");
  form2.set("txtSchNm", name ?? "");
  form2.set("txtAgcNmP", org ?? "");
  // 나머지 파라미터는 비워도 되게 원본이 비움. 필요시 추가 가능.

  const resp = await cookieFetch("https://m.kri.go.kr/kri/mobile/PG-RP-101-01jl.jsp", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      "Origin": "https://m.kri.go.kr",
      "Referer": "https://m.kri.go.kr/kri/mobile/KRI_RP_MO_001.jsp",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    },
    body: form2.toString()
  });

  const html = await resp.text();
  return { status: resp.status, html };
}

// 헬스체크
app.get("/health", (req, res) => res.json({ ok: true }));

// 검색 API
app.post("/search", auth, async (req, res) => {
  try {
    const { name, org } = req.body || {};
    if (!name || !org) {
      return res.status(400).json({ ok: false, error: "name and org are required" });
    }

    const t0 = Date.now();
    const out = await kriSearch({ name, org });
    const ms = Date.now() - t0;

    // 너무 큰 HTML을 n8n으로 보내는 게 부담이면 일부만 또는 파싱해서 반환 추천.
    res.json({
      ok: true,
      tookMs: ms,
      kriStatus: out.status,
      html: out.html
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e?.message || "Unknown error"
    });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`kri-relay listening on ${port}`));
