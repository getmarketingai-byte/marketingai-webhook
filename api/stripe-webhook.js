const crypto = require("crypto");

const ADMIN_EMAIL = "getmarketingai@gmail.com";
const CALENDLY_URL = "https://calendly.com/getmarketingai/30min";

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function verifyStripeWebhook(rawBody, sig, secret) {
  if (!sig) throw new Error("Missing stripe-signature header");
  if (!secret) throw new Error("STRIPE_WEBHOOK_SECRET not set");
  const parts = {};
  sig.split(",").forEach((p) => {
    const idx = p.indexOf("=");
    parts[p.slice(0, idx)] = p.slice(idx + 1);
  });
  if (!parts.t || !parts.v1) throw new Error("Malformed stripe-signature");
  const payload = parts.t + "." + rawBody.toString("utf8");
  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload, "utf8")
    .digest("hex");
  if (
    expected.length !== parts.v1.length ||
    !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))
  ) {
    throw new Error("Stripe signature mismatch");
  }
  if (Math.abs(Date.now() / 1000 - parseInt(parts.t, 10)) > 300) {
    throw new Error("Webhook timestamp too old");
  }
  return JSON.parse(rawBody.toString("utf8"));
}

function getTransport() {
  const nodemailer = require("nodemailer");
  return nodemailer.createTransporter({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.GMAIL_USER || ADMIN_EMAIL,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

async function sendWelcomeEmail(toEmail, toName) {
  const name = toName ? toName.split(" ")[0] : "there";
  const transport = getTransport();
  const lines = [
    "Hi " + name + ",",
    "",
    "Payment confirmed -- welcome to MarketingAI.",
    "",
    "You are getting three AI-assisted marketing systems:",
    "",
    "1. AI Content Engine",
    "   30-day LinkedIn content calendar. 10 posts, 4 themes, copy-paste ready.",
    "",
    "2. Outbound Lead Sequence",
    "   LinkedIn connection request + 2 DM follow-up templates.",
    "",
    "3. Email Nurture Sequence",
    "   3 emails: intro, value, low-pressure CTA. Formatted and ready to load.",
    "",
    "NEXT STEP: Book your 45-minute discovery call:",
    CALENDLY_URL,
    "",
    "Delivery within 3-5 business days. One free revision included.",
    "",
    "Reply here with any questions.",
    "",
    "-- The MarketingAI Team",
    ADMIN_EMAIL,
  ];
  await transport.sendMail({
    from: "MarketingAI <" + ADMIN_EMAIL + ">",
    to: toEmail,
    subject: "Welcome to MarketingAI -- book your discovery call",
    text: lines.join("\n"),
  });
  console.log("[webhook] Welcome email sent to", toEmail);
}

async function sendAdminNotification(clientEmail, clientName, amountCents, paymentId) {
  const transport = getTransport();
  const amount = amountCents ? "$" + (amountCents / 100).toFixed(2) : "unknown";
  const now = new Date().toLocaleString("en-AU", { timeZone: "Australia/Sydney" });
  const lines = [
    "New client at " + now + " AEST",
    "",
    "Name:       " + (clientName || "(not provided)"),
    "Email:      " + clientEmail,
    "Amount:     " + amount + " AUD",
    "Payment ID: " + (paymentId || "n/a"),
    "",
    "Welcome email sent. Client will book discovery call via Calendly.",
    "",
    "-- MarketingAI Webhook",
  ];
  await transport.sendMail({
    from: "MarketingAI Webhook <" + ADMIN_EMAIL + ">",
    to: ADMIN_EMAIL,
    subject: "[NEW CLIENT] " + (clientName || clientEmail) + " -- " + amount + " AUD",
    text: lines.join("\n"),
  });
  console.log("[webhook] Admin notification sent for", clientEmail);
}

module.exports = async (req, res) => {
  if (req.method === "GET") {
    let nodemailerOk = false;
    try {
      require("nodemailer");
      nodemailerOk = true;
    } catch (e) {
      /* unavailable */
    }
    return res.status(200).json({
      status: "ok",
      service: "marketingai-webhook",
      nodemailer: nodemailerOk,
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (e) {
    return res.status(500).json({ error: "Failed to read body" });
  }

  let event;
  try {
    event = verifyStripeWebhook(
      rawBody,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (e) {
    console.error("[webhook] Verification failed:", e.message);
    return res.status(400).json({ error: e.message });
  }

  console.log("[webhook] Received:", event.type, "(" + event.id + ")");

  try {
    if (event.type === "checkout.session.completed") {
      const s = event.data.object;
      if (s.payment_status !== "paid") {
        return res.status(200).json({ received: true, skipped: "not paid" });
      }
      const email =
        (s.customer_details && s.customer_details.email) || s.customer_email;
      const name = (s.customer_details && s.customer_details.name) || "";
      if (!email) {
        return res.status(200).json({ received: true, warning: "no email" });
      }
      await sendWelcomeEmail(email, name);
      await sendAdminNotification(email, name, s.amount_total, s.payment_intent);
    } else if (event.type === "payment_intent.succeeded") {
      const intent = event.data.object;
      const email = intent.receipt_email;
      const name =
        (intent.shipping && intent.shipping.name) ||
        (intent.metadata && intent.metadata.name) ||
        "";
      if (email) {
        await sendWelcomeEmail(email, name);
        await sendAdminNotification(email, name, intent.amount, intent.id);
      }
    }
  } catch (e) {
    console.error("[webhook] Processing error:", e.message);
    return res.status(200).json({ received: true, processingError: e.message });
  }

  return res.status(200).json({ received: true });
};
