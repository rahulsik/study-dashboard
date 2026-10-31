# Study Dashboard Server

Asli login: naya account Gmail ya mobile number se, OTP verify ke baad.

## Chalane ke steps
1. Node.js 20+ install karo.
2. Is folder mein: `npm install`
3. `.env.example` ko `.env` naam se copy karo.
4. `npm start` chalao, phir http://localhost:3000 kholo.

## OTP kaise aayega
- **Keys khali chhodo:** OTP server ke terminal mein print hoga (sirf testing ke liye).
- **Gmail:** Google account mein 2-step verification on karo, "App passwords" se password banao, `SMTP_USER` (apna Gmail) aur `SMTP_PASS` mein daalo.
- **Mobile number:** Twilio account banao, `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM` bharo. Twilio trial mein SMS sirf verified numbers par jaata hai. India mein SMS ke liye DLT rules lagte hain, to local provider (MSG91 etc.) lena pad sakta hai.

## Online daalna
Render ya Railway par daalo, `.env` ki values wahan Environment Variables mein dalo, `NODE_ENV=production` rakho, aur `DB_FILE` ko persistent disk par point karo, warna data restart par ud jaayega.

## Security notes
Passwords bcrypt se hash hote hain. OTP 10 minute mein expire hota hai, 5 galat try ke baad band. Rate limit laga hai. Server restart par rate limit counters reset ho jaate hain.
