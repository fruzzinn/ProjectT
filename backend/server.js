const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors()); // Allow frontend to access the backend
app.use(express.json()); // Parse JSON requests

// Mock Data
const newsData = [
  { title: "New Cyber Attack", summary: "A major cyber attack was reported.", url: "https://example.com" },
  { title: "Security Breach", summary: "A new security vulnerability was discovered.", url: "https://example.com" }
];

// API Route to Fetch News
app.get("/news", (req, res) => {
  res.json(newsData);
});

// Start Server
const PORT = 8000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
