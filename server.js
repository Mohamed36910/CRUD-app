const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
require("dotenv").config();
const app = express();

app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.getConnection((err, connection) => {
  if (err) {
    console.log("Database connection failed:", err);
    return;
  }

  console.log("Connected to MySQL");
  connection.release();
});

function authenticateToken(req, res, next) {
  //The middleware
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Access token required",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: "Invalid or expired token",
      });
    }

    req.user = user;
    next();
  });
}

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({
      error: "Username and password must be strings",
    });
  }
  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }

  const cleanUsername = username.trim();
  if (!cleanUsername) {
    return res.status(400).json({
      error: "Username cannot be empty",
    });
  }

  if (cleanUsername.length > 50) {
    return res.status(400).json({
      error: "Username is too long",
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "Password must be at least 8 characters",
    });
  }

  let hashedPassword;

  try {
    hashedPassword = await bcrypt.hash(password, 10);
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      error: "Password hashing failed",
    });
  }

  const sql = "INSERT INTO users (username, password) VALUES (?, ?)";

  db.query(sql, [cleanUsername, hashedPassword], (err, result) => {
    if (err) {
      console.log(err);

      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({
          error: "Username already exists",
        });
      }

      return res.status(500).json({
        error: "Database error",
      });
    }

    res.status(201).json({
      message: "User registered successfully",
      id: result.insertId,
    });
  });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({
      error: "Username and password must be strings",
    });
  }
  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }
  const cleanUsername = username.trim();
  if (!cleanUsername) {
    return res.status(400).json({
      error: "Username cannot be empty",
    });
  }
  const sql = "SELECT * FROM users WHERE username = ?";

  db.query(sql, [cleanUsername], async (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({
        error: "Database error",
      });
    }

    if (results.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const user = results[0];

    let passwordMatch;

    try {
      passwordMatch = await bcrypt.compare(password, user.password);
    } catch (err) {
      console.log(err);

      return res.status(500).json({
        error: "Password verification failed",
      });
    }

    if (!passwordMatch) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const accessToken = jwt.sign(
      {
        userId: user.id,
        username: user.username,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const refreshToken = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const tokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const refreshTokenExpiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000,
    );

    db.query(
      `INSERT INTO refresh_tokens
   (user_id, token_hash, expires_at)
   VALUES (?, ?, ?)`,
      [user.id, tokenHash, refreshTokenExpiresAt],
      (err) => {
        if (err) {
          console.log(err);

          return res.status(500).json({
            error: "Database error",
          });
        }

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
          message: "Login successful",
          token: accessToken,
        });
      },
    );
  });
});

app.post("/api/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({
      error: "Refresh token required",
    });
  }

  const tokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  db.query(
    `SELECT * FROM refresh_tokens
     WHERE token_hash = ?`,
    [tokenHash],
    (err, results) => {
      if (err) {
        console.log(err);

        return res.status(500).json({
          error: "Database error",
        });
      }

      if (results.length === 0) {
        return res.status(403).json({
          error: "Invalid refresh token",
        });
      }

      const storedToken = results[0];

      // Token was already used/revoked
      if (storedToken.revoked_at !== null) {
        db.query(
          `UPDATE refresh_tokens
           SET revoked_at = NOW()
           WHERE user_id = ?
           AND revoked_at IS NULL`,
          [storedToken.user_id],
          (err) => {
            if (err) {
              console.log(err);

              return res.status(500).json({
                error: "Database error",
              });
            }

            return res.status(403).json({
              error: "Refresh token reuse detected",
            });
          },
        );

        return;
      }

      // Token has expired in the database
      if (new Date(storedToken.expires_at) <= new Date()) {
        return res.status(403).json({
          error: "Refresh token expired",
        });
      }

      jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
        if (err) {
          return res.status(403).json({
            error: "Invalid or expired refresh token",
          });
        }

        if (user.userId !== storedToken.user_id) {
          return res.status(403).json({
            error: "Invalid refresh token",
          });
        }

        // Revoke the old refresh token
        db.query(
          `UPDATE refresh_tokens
           SET revoked_at = NOW()
           WHERE id = ?`,
          [storedToken.id],
          (err) => {
            if (err) {
              console.log(err);

              return res.status(500).json({
                error: "Database error",
              });
            }

            const newAccessToken = jwt.sign(
              {
                userId: user.userId,
                username: user.username,
              },
              process.env.JWT_SECRET,
              {
                expiresIn: "15m",
              },
            );

            const newRefreshToken = jwt.sign(
              {
                userId: user.userId,
              },
              process.env.JWT_SECRET,
              {
                expiresIn: "7d",
              },
            );
            const newTokenHash = crypto
              .createHash("sha256")
              .update(newRefreshToken)
              .digest("hex");

            const newRefreshTokenExpiresAt = new Date(
              Date.now() + 7 * 24 * 60 * 60 * 1000,
            );

            db.query(
              `INSERT INTO refresh_tokens
               (user_id, token_hash, expires_at)
               VALUES (?, ?, ?)`,
              [user.userId, newTokenHash, newRefreshTokenExpiresAt],
              (err) => {
                if (err) {
                  console.log(err);

                  return res.status(500).json({
                    error: "Database error",
                  });
                }

                res.cookie("refreshToken", newRefreshToken, {
                  httpOnly: true,
                  secure: false,
                  sameSite: "lax",
                  maxAge: 7 * 24 * 60 * 60 * 1000,
                });

                res.json({
                  token: newAccessToken,
                });
              },
            );
          },
        );
      });
    },
  );
});

app.post("/api/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.json({
      message: "Logged out successfully",
    });
  }

  const tokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  db.query(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE token_hash = ?
     AND revoked_at IS NULL`,
    [tokenHash],
    (err) => {
      if (err) {
        console.log(err);

        return res.status(500).json({
          error: "Database error",
        });
      }

      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
      });

      res.json({
        message: "Logged out successfully",
      });
    },
  );
});

app.get("/api/auth/check", authenticateToken, (req, res) => {
  res.json({
    message: "Token is valid",
  });
});

app.get("/api/posts", (req, res) => {
  const sql = "SELECT * FROM posts";

  db.query(sql, (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json(results);
  });
});

app.get("/api/posts/search", (req, res) => {
  const search = req.query.search;

  if (!search) {
    return res.status(400).json({
      error: "Search term is required",
    });
  }

  const searchTerm = `%${search}%`;

  const sql = `
    SELECT * FROM posts
    WHERE title LIKE ? OR content LIKE ?
  `;

  db.query(sql, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.log(err);

      return res.status(500).json({
        error: "Database error",
      });
    }

    res.json(results);
  });
});

app.post("/api/posts", authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.userId;
  if (!title || !content) {
    return res.status(400).json({ error: "Title and content are required" });
  }

  if (title.length > 255) {
    return res.status(400).json({
      error: "Title is too long",
    });
  }

  const sql = "INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)";

  db.query(sql, [title, content, userId], (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json({
      message: "Post created successfully",
      id: result.insertId,
    });
  });
});

app.put("/api/posts/:id", authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const { id } = req.params;
  if (!/^\d+$/.test(id)) {
    return res.status(400).json({
      error: "Invalid post ID",
    });
  }

  if (!title || !content) {
    return res.status(400).json({
      error: "Title and content are required",
    });
  }

  if (title.length > 255) {
    return res.status(400).json({
      error: "Title is too long",
    });
  }

  const sql =
    "UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?";

  db.query(sql, [title, content, id, req.user.userId], (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Post not found",
      });
    }

    res.json({
      message: "Post updated successfully",
    });
  });
});

app.delete("/api/posts/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  if (!/^\d+$/.test(id)) {
    return res.status(400).json({
      error: "Invalid post ID",
    });
  }

  const sql = "DELETE FROM posts WHERE id = ? AND user_id = ?";

  db.query(sql, [id, req.user.userId], (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Post not found",
      });
    }

    res.json({
      message: "Post deleted successfully",
    });
  });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server is running");
});
