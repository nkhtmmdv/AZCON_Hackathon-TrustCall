# 🛡️ TrustCall — AI-Powered Call Protection

> Built at **AZCON Hackathon** — Protecting subscribers from scam, spam, and spoofed calls in real-time.

---

## 🚀 Live Demo

🔗 [https://azcon-hackathon-trust-call.vercel.app](https://azcon-hackathon-trust-call.vercel.app)

---

## 📌 About

**TrustCall** is a network-level call protection system that analyzes incoming calls before the user's phone even rings. It uses STIR/SHAKEN verification, behavioral pattern analysis, and crowdsourced threat intelligence to classify every call as **Safe**, **Spam**, or **Scam**.

Built for subscribers in Azerbaijan, TrustCall addresses the growing problem of phone fraud including bank impersonation, government spoofing, and investment scams.

---

## ✨ Features

- 🔍 **Real-time call analysis** — SIP signaling and STIR/SHAKEN header inspection
- 🧠 **AI risk scoring** — ML pipeline assigns danger level (0–100) to every call
- 📱 **Live call simulation** — Demo safe, spam, and scam call scenarios
- 🔎 **Number lookup** — Check any number against global threat intelligence
- 📊 **Admin dashboard** — Network-wide statistics, threat map, blocked call analytics
- 👥 **Crowdsourced reports** — Users report suspicious numbers, community consensus triggers auto-block
- 🚫 **Personal & global blacklists** — User-level and network-level blocking
- 🔐 **Auth system** — User and admin roles with session management

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS v4 |
| Animations | Framer Motion |
| Charts | Recharts |
| Icons | Lucide React |
| Backend | Node.js, Express |
| Database | JSON (local), lowdb |
| Deployment | Vercel |

---

## 📂 Project Structure

```
├── src/
│   ├── App.tsx              # Main application
│   ├── index.css            # Global styles (Azercell theme)
│   ├── services/
│   │   ├── aiService.ts     # AI risk analysis
│   │   └── telecomService.ts # Call simulation & data
│   └── types/
│       └── telecom.ts       # TypeScript types
├── server/
│   ├── index.ts             # Express API server
│   ├── auth.ts              # Authentication
│   ├── db.ts                # Database layer
│   └── util.ts              # Utilities
└── public/
    └── company-numbers.json # Verified company numbers
```

---

## 🏃 Getting Started

### Prerequisites
- Node.js 18+
- npm

### Installation

```bash
# Clone the repo
git clone https://github.com/nkhtmmdv/AZCON_Hackathon-TrustCall.git
cd AZCON_Hackathon-TrustCall

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Start frontend
npm run dev

# Start backend (separate terminal)
npm run server
```

Frontend runs on `http://localhost:5173`
Backend runs on `http://localhost:3000`

---

## 🎮 Demo Credentials

| Role | Email | Password |
|------|-------|----------|
| User | user@example.com | password |
| Admin | admin@example.com | password |

---

## 🔒 How It Works

1. **Incoming call detected** → SIP headers extracted
2. **STIR/SHAKEN verification** → Attestation level checked (A/B/C)
3. **Behavioral analysis** → Call pattern, frequency, origin analyzed
4. **Crowdsourced data** → Community reports factored in
5. **Risk score generated** → 0–100 danger level assigned
6. **Action taken** → Allow / Warn / Block before phone rings

---

## 👥 Team

Built with ❤️ at **AZCON Hackathon 2026**

| Name |
|------|
| Nihat Mamedov |
| Meltem Gasimova |
| Fidan Aslanova |
| Farid Mahmudlu |

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) for details.
