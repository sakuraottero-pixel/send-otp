import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());

const API_KEY = process.env.API_KEY;
const API_SECRET = process.env.API_SECRET;
const APP_ID = process.env.APP_ID;

// temporary OTP store (production এ Redis/DB)
const otpStore = new Map();

// generate OTP
const genOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post("/send-otp", async (req, res) => {
  const { number } = req.body;
  if (!number) return res.status(400).json({ error: "number required" });

  const otp = genOTP();
  const message = `Your OTP is ${otp}. Your OTP is ${otp}.`;

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
        content: message,
        senderId: "Promo Shop",
        orderId: number
      })
    });

    const data = await r.json();

    // save OTP (5 min expiry)
    otpStore.set(number, {
      otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    res.json({ success: true, api: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// verify OTP
app.post("/verify-otp", (req, res) => {
  const { number, otp } = req.body;
  const record = otpStore.get(number);

  if (!record) return res.json({ success: false, msg: "OTP sending failed" });
  if (Date.now() > record.expires)
    return res.json({ success: false, msg: "OTP expired" });

  if (record.otp !== otp)
    return res.json({ success: false, msg: "Invalid OTP" });

  otpStore.delete(number);
  res.json({ success: true, msg: "OTP verification successful" });
});

app.listen(3000, () => console.log("server running"));
