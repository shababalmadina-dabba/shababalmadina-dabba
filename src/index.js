export default {
async fetch(request, env) {
const url = new URL(request.url);

if (url.pathname === "/api/membership" && request.method === "POST") {
  try {
    const data = await request.json();

    const fullName = String(data.full_name || "").trim();
    const phone = String(data.phone || "").trim();
    const address = String(data.address || "").trim();
    const birthDate = String(data.birth_date || "").trim();
    const occupation = String(data.occupation || "").trim();
    const membershipType = String(data.membership_type || "").trim();

    if (fullName.length < 3 || fullName.length > 150) {
      return Response.json(
        { success: false, message: "يرجى إدخال الاسم الكامل بصورة صحيحة." },
        { status: 400 }
      );
    }

    if (phone.length < 6 || phone.length > 30) {
      return Response.json(
        { success: false, message: "يرجى إدخال رقم هاتف صحيح." },
        { status: 400 }
      );
    }

    if (address.length < 2 || address.length > 200) {
      return Response.json(
        { success: false, message: "يرجى إدخال العنوان." },
        { status: 400 }
      );
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(birthDate) ||
        Number.isNaN(Date.parse(birthDate))) {
      return Response.json(
        { success: false, message: "يرجى إدخال تاريخ الميلاد بصورة صحيحة." },
        { status: 400 }
      );
    }

    if (occupation.length < 2 || occupation.length > 100) {
      return Response.json(
        { success: false, message: "يرجى إدخال المهنة." },
        { status: 400 }
      );
    }

    if (!["عضو عامل", "عضو منتسب"].includes(membershipType)) {
      return Response.json(
        { success: false, message: "يرجى اختيار نوع العضوية." },
        { status: 400 }
      );
    }

    await env.DB.prepare(
      `INSERT INTO membership_requests
       (full_name, phone, address, birth_date, occupation, membership_type, status)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        fullName,
        phone,
        address,
        birthDate,
        occupation,
        membershipType,
        "pending"
      )
      .run();

    return Response.json(
      {
        success: true,
        message: "تم استلام طلب العضوية بنجاح. يرجى إكمال خطوة إشعار الدفع."
      },
      { status: 201 }
    );
  } catch (error) {
    return Response.json(
      {
        success: false,
        message: "تعذر إرسال الطلب. يرجى المحاولة لاحقًا."
      },
      { status: 500 }
    );
  }
}

if (url.pathname.startsWith("/api/")) {
  return Response.json(
    { success: false, message: "المسار غير موجود." },
    { status: 404 }
  );
}

return env.ASSETS.fetch(request);

}
};