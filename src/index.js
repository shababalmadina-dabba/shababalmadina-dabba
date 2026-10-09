function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers });
}

function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");

  const binary = atob(
    normalized + "=".repeat((4 - normalized.length % 4) % 4)
  );

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function signSession(expiry, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(expiry)
  );

  return base64url(new Uint8Array(signature));
}

async function isAdmin(request, secret) {
  if (!secret) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)club_admin=([^;]+)/);

  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const [expiry, signature] = parts;

  if (!/^\d+$/.test(expiry)) return false;

  if (Number(expiry) < Math.floor(Date.now() / 1000)) {
    return false;
  }

  try {
    const expected = await signSession(expiry, secret);
    const actualBytes = decodeBase64url(signature);
    const expectedBytes = decodeBase64url(expected);

    if (actualBytes.length !== expectedBytes.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actualBytes.length; i++) {
      difference |= actualBytes[i] ^ expectedBytes[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

function sessionCookie(value, maxAge) {
  return [
    `club_admin=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${maxAge}`
  ].join("; ");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // فحص إعدادات الإدارة دون إظهار كلمة المرور.
    if (
      path === "/api/admin/check-config" &&
      request.method === "GET"
    ) {
      return json(
        {
          configured:
            typeof env.ADMIN_PASSWORD === "string" &&
            env.ADMIN_PASSWORD.length > 0
        },
        200,
        { "Cache-Control": "no-store" }
      );
    }

    // صفحة إدارة العضوية.
    if (
      request.method === "GET" &&
      (path === "/admin" || path === "/admin/")
    ) {
      return env.ASSETS.fetch(
        new Request(new URL("/admin.html", url), request)
      );
    }

    // صفحة إدارة الأخبار.
    if (
      request.method === "GET" &&
      (path === "/news-admin" || path === "/news-admin/")
    ) {
      return env.ASSETS.fetch(
        new Request(new URL("/news-admin.html", url), request)
      );
    }

    // صفحة الأخبار العامة.
    if (
      request.method === "GET" &&
      (path === "/news" || path === "/news/")
    ) {
      return env.ASSETS.fetch(
        new Request(new URL("/news.html", url), request)
      );
    }

    // تسجيل دخول المسؤول.
    if (
      path === "/api/admin/login" &&
      request.method === "POST"
    ) {
      if (
        typeof env.ADMIN_PASSWORD !== "string" ||
        env.ADMIN_PASSWORD.length === 0
      ) {
        return json(
          {
            success: false,
            message: "إعدادات الإدارة غير مكتملة."
          },
          500,
          { "Cache-Control": "no-store" }
        );
      }

      try {
        const data = await request.json();
        const password =
          typeof data.password === "string"
            ? data.password
            : "";

        if (
          password.length === 0 ||
          password.length > 1024 ||
          password !== env.ADMIN_PASSWORD
        ) {
          return json(
            {
              success: false,
              message: "كلمة المرور غير صحيحة."
            },
            401,
            { "Cache-Control": "no-store" }
          );
        }

        const expiry = String(
          Math.floor(Date.now() / 1000) + 8 * 60 * 60
        );

        const signature = await signSession(
          expiry,
          env.ADMIN_PASSWORD
        );

        return json(
          {
            success: true,
            message: "تم تسجيل الدخول بنجاح."
          },
          200,
          {
            "Set-Cookie": sessionCookie(
              `${expiry}.${signature}`,
              8 * 60 * 60
            ),
            "Cache-Control": "no-store"
          }
        );
      } catch {
        return json(
          {
            success: false,
            message: "تعذر تسجيل الدخول."
          },
          400,
          { "Cache-Control": "no-store" }
        );
      }
    }

    // تسجيل الخروج.
    if (
      path === "/api/admin/logout" &&
      request.method === "POST"
    ) {
      return json(
        {
          success: true,
          message: "تم تسجيل الخروج."
        },
        200,
        {
          "Set-Cookie": sessionCookie("", 0),
          "Cache-Control": "no-store"
        }
      );
    }

    // الأخبار المنشورة: واجهة عامة للقراءة فقط.
    if (
      path === "/api/news" &&
      request.method === "GET"
    ) {
      try {
        if (!env.NEWS_DB) {
          throw new Error("NEWS_DB binding is missing");
        }

        const result = await env.NEWS_DB.prepare(`
          SELECT id, title, content, created_at, updated_at
          FROM news
          ORDER BY id DESC
          LIMIT 100
        `).all();

        return json(
          {
            success: true,
            news: result.results || []
          },
          200,
          {
            "Cache-Control": "no-store"
          }
        );
      } catch {
        return json(
          {
            success: false,
            message: "تعذر تحميل الأخبار."
          },
          500,
          {
            "Cache-Control": "no-store"
          }
        );
      }
    }

    // حماية جميع واجهات الإدارة.
    if (path.startsWith("/api/admin/")) {
      const authenticated = await isAdmin(
        request,
        env.ADMIN_PASSWORD
      );

      if (!authenticated) {
        return json(
          {
            success: false,
            message: "يرجى تسجيل الدخول أولًا."
          },
          401,
          { "Cache-Control": "no-store" }
        );
      }

      // عرض طلبات العضوية للإدارة.
      if (
        path === "/api/admin/requests" &&
        request.method === "GET"
      ) {
        try {
          const result = await env.DB.prepare(`
            SELECT
              id,
              full_name,
              phone,
              address,
              birth_date,
              occupation,
              membership_type,
              status,
              membership_number,
              created_at
            FROM membership_requests
            ORDER BY id DESC
          `).all();

          return json(
            {
              success: true,
              requests: result.results || []
            },
            200,
            { "Cache-Control": "no-store" }
          );
        } catch {
          return json(
            {
              success: false,
              message: "تعذر تحميل الطلبات."
            },
            500,
            { "Cache-Control": "no-store" }
          );
        }
      }

      // عرض جميع الأخبار في لوحة الإدارة.
      if (
        path === "/api/admin/news" &&
        request.method === "GET"
      ) {
        try {
          if (!env.NEWS_DB) {
            throw new Error("NEWS_DB binding is missing");
          }

          const result = await env.NEWS_DB.prepare(`
            SELECT id, title, content, created_at, updated_at
            FROM news
            ORDER BY id DESC
          `).all();

          return json(
            {
              success: true,
              news: result.results || []
            },
            200,
            { "Cache-Control": "no-store" }
          );
        } catch {
          return json(
            {
              success: false,
              message: "تعذر تحميل الأخبار للإدارة."
            },
            500,
            { "Cache-Control": "no-store" }
          );
        }
      }

      // نشر خبر جديد.
      if (
        path === "/api/admin/news" &&
        request.method === "POST"
      ) {
        try {
          if (!env.NEWS_DB) {
            throw new Error("NEWS_DB binding is missing");
          }

          const data = await request.json();

          const title =
            typeof data.title === "string"
              ? data.title.trim()
              : "";

          const content =
            typeof data.content === "string"
              ? data.content.trim()
              : "";

          if (title.length < 2 || title.length > 200) {
            return json(
              {
                success: false,
                message: "يجب أن يكون عنوان الخبر بين حرفين و200 حرف."
              },
              400
            );
          }

          if (content.length < 1 || content.length > 10000) {
            return json(
              {
                success: false,
                message: "نص الخبر مطلوب، والحد الأقصى 10000 حرف."
              },
              400
            );
          }

          const result = await env.NEWS_DB.prepare(`
            INSERT INTO news (title, content)
            VALUES (?, ?)
          `).bind(title, content).run();

          return json(
            {
              success: true,
              message: "تم نشر الخبر بنجاح.",
              id: result.meta?.last_row_id ?? null
            },
            201,
            { "Cache-Control": "no-store" }
          );
        } catch {
          return json(
            {
              success: false,
              message: "تعذر نشر الخبر."
            },
            500,
            { "Cache-Control": "no-store" }
          );
        }
      }

      // التحقق من مسار تعديل خبر أو حذفه.
      const newsMatch = path.match(
        /^\/api\/admin\/news\/(\d+)$/
      );

      if (newsMatch) {
        const id = Number(newsMatch[1]);

        if (!Number.isSafeInteger(id) || id < 1) {
          return json(
            {
              success: false,
              message: "رقم الخبر غير صحيح."
            },
            400
          );
        }

        // تعديل خبر موجود.
        if (request.method === "PATCH") {
          try {
            if (!env.NEWS_DB) {
              throw new Error("NEWS_DB binding is missing");
            }

            const data = await request.json();

            const title =
              typeof data.title === "string"
                ? data.title.trim()
                : "";

            const content =
              typeof data.content === "string"
                ? data.content.trim()
                : "";

            if (title.length < 2 || title.length > 200) {
              return json(
                {
                  success: false,
                  message: "يجب أن يكون عنوان الخبر بين حرفين و200 حرف."
                },
                400
              );
            }

            if (content.length < 1 || content.length > 10000) {
              return json(
                {
                  success: false,
                  message: "نص الخبر مطلوب، والحد الأقصى 10000 حرف."
                },
                400
              );
            }

            const existing = await env.NEWS_DB.prepare(`
              SELECT id FROM news WHERE id = ?
            `).bind(id).first();

            if (!existing) {
              return json(
                {
                  success: false,
                  message: "الخبر غير موجود."
                },
                404
              );
            }

            await env.NEWS_DB.prepare(`
              UPDATE news
              SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `).bind(title, content, id).run();

            return json(
              {
                success: true,
                message: "تم تعديل الخبر بنجاح."
              },
              200,
              { "Cache-Control": "no-store" }
            );
          } catch {
            return json(
              {
                success: false,
                message: "تعذر تعديل الخبر."
              },
              500,
              { "Cache-Control": "no-store" }
            );
          }
        }

        // حذف خبر.
        if (request.method === "DELETE") {
          try {
            if (!env.NEWS_DB) {
              throw new Error("NEWS_DB binding is missing");
            }

            const result = await env.NEWS_DB.prepare(`
              DELETE FROM news WHERE id = ?
            `).bind(id).run();

            if (!result.meta || result.meta.changes === 0) {
              return json(
                {
                  success: false,
                  message: "الخبر غير موجود أو سبق حذفه."
                },
                404
              );
            }

            return json(
              {
                success: true,
                message: "تم حذف الخبر بنجاح."
              },
              200,
              { "Cache-Control": "no-store" }
            );
          } catch {
            return json(
              {
                success: false,
                message: "تعذر حذف الخبر."
              },
              500,
              { "Cache-Control": "no-store" }
            );
          }
        }

        return json(
          {
            success: false,
            message: "طريقة الطلب غير مدعومة."
          },
          405
        );
      }

      // قبول طلب عضوية أو رفضه.
      const requestMatch = path.match(
        /^\/api\/admin\/requests\/(\d+)$/
      );

      if (
        requestMatch &&
        request.method === "PATCH"
      ) {
        const id = Number(requestMatch[1]);

        if (!Number.isSafeInteger(id) || id < 1) {
          return json(
            {
              success: false,
              message: "رقم الطلب غير صحيح."
            },
            400
          );
        }

        try {
          const data = await request.json();
          const status = data.status;

          if (!["approved", "rejected"].includes(status)) {
            return json(
              {
                success: false,
                message: "حالة الطلب غير صحيحة."
              },
              400
            );
          }

          if (status === "approved") {
            await env.DB.prepare(`
              UPDATE membership_requests
              SET
                status = 'approved',
                membership_number = COALESCE(
                  membership_number,
                  'SM-' || printf('%06d', id)
                )
              WHERE id = ?
            `).bind(id).run();
          } else {
            await env.DB.prepare(`
              UPDATE membership_requests
              SET status = 'rejected'
              WHERE id = ?
            `).bind(id).run();
          }

          const member = await env.DB.prepare(`
            SELECT
              id,
              full_name,
              status,
              membership_number
            FROM membership_requests
            WHERE id = ?
          `).bind(id).first();

          if (!member) {
            return json(
              {
                success: false,
                message: "الطلب غير موجود."
              },
              404
            );
          }

          return json({
            success: true,
            message:
              status === "approved"
                ? "تم قبول الطلب وتخصيص رقم العضوية."
                : "تم رفض الطلب.",
            member
          });
        } catch {
          return json(
            {
              success: false,
              message: "تعذر تحديث الطلب."
            },
            500
          );
        }
      }

      return json(
        {
          success: false,
          message: "مسار الإدارة غير موجود."
        },
        404
      );
    }

    // قائمة الأعضاء العامة: الاسم ورقم العضوية فقط.
    if (
      path === "/api/members" &&
      request.method === "GET"
    ) {
      try {
        const result = await env.DB.prepare(`
          SELECT
            full_name,
            membership_number
          FROM membership_requests
          WHERE status = 'approved'
            AND membership_number IS NOT NULL
            AND membership_number != ''
          ORDER BY id DESC
        `).all();

        return json(
          {
            success: true,
            members: result.results || []
          },
          200,
          {
            "Cache-Control": "no-store"
          }
        );
      } catch {
        return json(
          {
            success: false,
            message: "تعذر تحميل قائمة الأعضاء."
          },
          500,
          {
            "Cache-Control": "no-store"
          }
        );
      }
    }

    // استقبال طلب عضوية جديد.
    if (
      path === "/api/membership" &&
      request.method === "POST"
    ) {
      try {
        const data = await request.json();

        const fullName = String(data.full_name || "").trim();
        const phone = String(data.phone || "").trim();
        const address = String(data.address || "").trim();
        const birthDate = String(data.birth_date || "").trim();
        const occupation = String(data.occupation || "").trim();
        const membershipType = String(
          data.membership_type || ""
        ).trim();

        if (fullName.length < 3 || fullName.length > 150) {
          return json(
            {
              success: false,
              message: "يرجى إدخال الاسم الكامل بصورة صحيحة."
            },
            400
          );
        }

        if (phone.length < 6 || phone.length > 30) {
          return json(
            {
              success: false,
              message: "يرجى إدخال رقم هاتف صحيح."
            },
            400
          );
        }

        if (address.length < 2 || address.length > 200) {
          return json(
            {
              success: false,
              message: "يرجى إدخال العنوان."
            },
            400
          );
        }

        if (
          birthDate &&
          (
            !/^\d{4}-\d{2}-\d{2}$/.test(birthDate) ||
            Number.isNaN(Date.parse(birthDate))
          )
        ) {
          return json(
            {
              success: false,
              message: "يرجى إدخال تاريخ الميلاد بصورة صحيحة."
            },
            400
          );
        }

        if (occupation.length > 100) {
          return json(
            {
              success: false,
              message: "المهنة طويلة جدًا."
            },
            400
          );
        }

        if (
          ![
            "عضو عامل",
            "عضو منتسب",
            "عضوية عامة"
          ].includes(membershipType)
        ) {
          return json(
            {
              success: false,
              message: "يرجى اختيار نوع العضوية."
            },
            400
          );
        }

        await env.DB.prepare(`
          INSERT INTO membership_requests (
            full_name,
            phone,
            address,
            birth_date,
            occupation,
            membership_type,
            status
          )
          VALUES (?, ?, ?, ?, ?, ?, 'pending')
        `).bind(
          fullName,
          phone,
          address,
          birthDate || null,
          occupation || null,
          membershipType
        ).run();

        return json(
          {
            success: true,
            message:
              "تم استلام طلب العضوية بنجاح. يرجى إكمال خطوة إشعار الدفع."
          },
          201
        );
      } catch {
        return json(
          {
            success: false,
            message: "تعذر إرسال الطلب. يرجى المحاولة لاحقًا."
          },
          500
        );
      }
    }

    // معالجة مسارات API غير المعروفة.
    if (path.startsWith("/api/")) {
      return json(
        {
          success: false,
          message: "المسار غير موجود."
        },
        404
      );
    }

    // بقية ملفات الموقع.
    return env.ASSETS.fetch(request);
  }
};