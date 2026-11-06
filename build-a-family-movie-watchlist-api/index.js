
import express from "express";
import helmet from "helmet";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { authenticate } from "./middleware/authenticate.js";
import { authorizeModification } from "./middleware/authorize.js";
import {
  findByUsername,
  findById,
  getWatchlist,
  addMovie,
  updateMovie,
  deleteMovie,
} from "./utils/db.js";

const PORT = process.env.PORT || 3000;
const app = express();

app.use(helmet());
app.use(express.json());

// Helper function to resolve numeric vs. string userId
function getValidUserId(userId) {
  if (findById(userId)) return userId;

  const num = Number(userId);
  if (!isNaN(num) && findById(num)) return num;

  const str = String(userId);
  if (findById(str)) return str;

  return userId;
}

// Root Endpoint
app.get("/", (req, res) => {
  res.send("Family Movie Watchlist API");
});

// Auth Route: Login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  const user = findByUsername(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  let isMatch = false;

  try {
    isMatch = await bcrypt.compare(password, user.passwordHash);
  } catch {
    isMatch = false;
  }

  if (!isMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET || "secret",
    { expiresIn: "1h" }
  );

  return res.status(200).json({ token });
});

// Watchlist Route: GET User Watchlist
app.get("/api/watchlist/:userId", authenticate, (req, res) => {
  const { userId } = req.params;
  const validId = getValidUserId(userId);
  const watchlist = getWatchlist(validId);

  return res.status(200).json(watchlist || []);
});

// Watchlist Route: POST Add Movie
app.post(
  "/api/watchlist/:userId/movies",
  authenticate,
  authorizeModification,
  (req, res) => {
    const { userId } = req.params;
    const validId = getValidUserId(userId);
    const movie = addMovie(validId, req.body);

    return res.status(201).json(movie);
  }
);

// Watchlist Route: PUT Update Movie
app.put(
  "/api/watchlist/:userId/movies/:movieId",
  authenticate,
  authorizeModification,
  (req, res) => {
    const { userId, movieId } = req.params;
    const validId = getValidUserId(userId);
    const movie = updateMovie(validId, Number(movieId), req.body);

    return res.status(200).json(movie);
  }
);

// Watchlist Route: DELETE Remove Movie
app.delete(
  "/api/watchlist/:userId/movies/:movieId",
  authenticate,
  authorizeModification,
  (req, res) => {
    const { userId, movieId } = req.params;
    const validId = getValidUserId(userId);
    deleteMovie(validId, Number(movieId));

    return res.status(200).json({ message: "Movie deleted" });
  }
);

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}...`);
});
