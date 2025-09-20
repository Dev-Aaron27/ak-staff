import express from "express";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

// ⚙️ Config
const CLIENT_ID = process.env.DISCORD_CLIENT_ID || "YOUR_DISCORD_CLIENT_ID";
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "YOUR_DISCORD_CLIENT_SECRET";
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:3000/callback.html"; 
const JWT_SECRET = process.env.JWT_SECRET || "supersecretjwt";

// 1️⃣ Redirect to Discord OAuth2
app.get("/auth/discord", (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&response_type=code&scope=identify%20guilds`;
  res.redirect(url);
});

// 2️⃣ Handle Discord OAuth2 callback
app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).json({ error: "No code provided" });

  // Exchange code for token
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      scope: "identify guilds"
    }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    return res.status(400).json({ error: "Failed to get token" });
  }

  // Fetch Discord user profile
  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  const userData = await userRes.json();

  // Create JWT
  const payload = {
    discord_id: userData.id,
    username: userData.username,
    discriminator: userData.discriminator,
    avatar: userData.avatar
  };
  const jwtToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

  // Redirect back to frontend with token in URL
  res.redirect(`${REDIRECT_URI}?token=${jwtToken}`);
});

// 3️⃣ Verify token
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "No token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (e) {
    res.status(403).json({ valid: false, error: "Invalid token" });
  }
});

app.listen(4000, () =>
  console.log("✅ Auth API running on http://localhost:4000")
);
