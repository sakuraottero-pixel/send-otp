import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());

const { API_KEY, API_SECRET, APP_ID } = process.env;

// in-memory OTP store
const otpStore = new Map();

const genOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post("/send-otp", async (req, res) => {
  const { number } = req.body;
  if (!number) return res.status(400).json({ error: "number required" });

  const otp = genOTP();
  const msg = `Your OTP is ${otp}.  Your OTP is ${otp}.`;

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sign = crypto
    .createHash("md5")
    .update(API_KEY + API_SECRET + timestamp)
    .digest("hex");

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

  otpStore.set(number, {
    otp,
    expires: Date.now() + 5 * 60 * 1000
  });

  res.json({ success: true, api: data });
});

app.post("/verify-otp", (req, res) => {
  const { number, otp } = req.body;
  const record = otpStore.get(number);

  if (!record) return res.json({ ok: false, msg: "OTP sending failed" });
  if (Date.now() > record.expires)
    return res.json({ ok: false, msg: "OTP expired" });
  if (record.otp !== otp)
    return res.json({ ok: false, msg: "Wrong OTP entered" });

  otpStore.delete(number);
  res.json({ ok: true, msg: "OTP verification successful" });
});

app.listen(3000, () => console.log("server running"));
