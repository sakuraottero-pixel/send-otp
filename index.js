import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Env vars
const { API_KEY, API_SECRET, APP_ID } = process.env;

// OTP store (production: Redis/DB)
const otpStore = new Map();

// Rate limit map
const rateLimit = new Map();

// Generate 6-digit OTP
const genOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP endpoint
app.post("/send-otp", async (req, res) => {
  const { number } = req.body;
  if (!number) return res.status(400).json({ error: "Number required" });

  // Rate limit check: 1 OTP / 60 sec
  const lastSent = rateLimit.get(number);
  if (lastSent && Date.now() - lastSent < 60 * 1000)
    return res.status(429).json({ error: "Wait 60 seconds before requesting again" });

  const otp = genOTP();
  const msg = `Your OTP is ${otp}. Valid for 5 minutes.`;

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sign = crypto
    .createHash("md5")
    .update(API_KEY + API_SECRET + timestamp)
    .digest("hex");

  try {
    const r = await fetch("https://api.laaffic.com/v3/sendSms", {
      method: "POST",
      headers: {
        "Content-Type": "application/json;charset=UTF-8",
        "Api-Key": API_KEY,
        "Timestamp": timestamp,
        "Sign": sign
      },
      body: JSON.stringify({
        appId: APP_ID,
        numbers: number,
        content: msg,
        senderId: "Promo Shop",
        orderId: number
      })
    });

    const data = await r.json();

    // Save OTP & timestamp
    otpStore.set(number, { otp, expires: Date.now() + 5 * 60 * 1000 });
    rateLimit.set(number, Date.now());

    res.json({ success: true, apiResponse: data });
  } catch (err) {
    res.status(500).json({ error: "SMS sending failed", details: err.message });
  }
});

// Verify OTP
app.post("/verify-otp", (req, res) => {
  const { number, otp } = req.body;
  const record = otpStore.get(number);

  if (!record) return res.json({ ok: false, msg: "OTP not found" });
  if (Date.now() > record.expires) return res.json({ ok: false, msg: "OTP expired" });
  if (record.otp !== otp) return res.json({ ok: false, msg: "Wrong OTP" });

  otpStore.delete(number);
  res.json({ ok: true, msg: "OTP verified successfully" });
});

// Start server
app.listen(3000, () => console.log("OTP server running"));
