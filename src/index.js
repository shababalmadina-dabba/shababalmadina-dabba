export default {
async fetch(request, env) {
const url = new URL(request.url);

if (url.pathname === "/api/membership" && request.method === "POST") {
  try {
    const data = await request.json();

    const fullName = String(data.full_name || "").trim();
    const phone = String(data.phone || "").trim();
    const paymentReference = String(data.payment_reference || "").trim();

    if (fullName.length < 3 || fullName.length > 150) {
      return Response.json(
        { success: false, message: "يرجى إدخال الاسم بصورة صحيحة." },
        { status: 400 }
      );
    }

    if (phone.length < 6 || phone.length > 30) {
      return Response.json(
        { success: false, message: "يرجى إدخال رقم هاتف صحيح." },
        { status: 400 }
      );
    }

    if (paymentReference.length > 100) {
      return Response.json(
        { success: false, message: "رقم مرجع الدفع غير صالح." },
        { status: 400 }
      );
    }

    await env.DB.prepare(
      `INSERT INTO membership_requests
       (full_name, phone, payment_reference)
       VALUES (?, ?, ?)`
    )
      .bind(fullName, phone, paymentReference || null)
      .run();

    return Response.json(
      {
        success: true,
        message: "تم استلام طلب العضوية بنجاح."
      },
      { status: 201 }
    );
  } catch (error) {
    return Response.json(
      { success: false, message: "تعذر إرسال الطلب. يرجى المحاولة لاحقًا." },
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
