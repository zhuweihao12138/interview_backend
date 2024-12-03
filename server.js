const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_secret_key"; // 请替换为更安全的密钥

// 中间件
app.use(cors());
app.use(bodyParser.json());

// 初始化 SQLite 数据库
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Failed to connect to database:", err.message);
  } else {
    console.log("Connected to SQLite database.");
    db.serialize(() => {
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT
        )`);

      db.run(`
        CREATE TABLE IF NOT EXISTS appointments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          date TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

      db.run(`
        CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          message TEXT NOT NULL,
          timestamp INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    });
  }
});

// JWT 认证中间件
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "未授权。" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token 无效。" });
    req.user = user;
    next();
  });
};

// 注册接口
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "用户名和密码不能为空。" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hashedPassword],
      (err) => {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ message: "用户名已被注册。" });
          }
          return res.status(500).json({ message: "注册失败。" });
        }
        res.status(201).json({ message: "注册成功！" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "注册失败。" });
  }
});

// 登录接口
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "用户名和密码不能为空。" });
  }

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ message: "登录失败。" });
      }

      if (!user) {
        return res.status(400).json({ message: "用户名或密码错误。" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(400).json({ message: "用户名或密码错误。" });
      }

      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
        expiresIn: "1h",
      });

      res.status(200).json({ token });
    }
  );
});

// 获取预约接口
app.get("/api/appointments", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    `SELECT * FROM appointments WHERE user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "获取预约失败。" });
      res.status(200).json(rows);
    }
  );
});

// 添加预约接口
app.post("/api/appointments", authenticateToken, (req, res) => {
  const { title, date } = req.body;
  const userId = req.user.id;

  if (!title || !date) {
    return res.status(400).json({ message: "标题和日期不能为空。" });
  }

  db.run(
    `INSERT INTO appointments (user_id, title, date) VALUES (?, ?, ?)`,
    [userId, title, date],
    function (err) {
      if (err) return res.status(500).json({ message: "添加预约失败。" });

      db.run(
        `INSERT INTO logs (user_id, message, timestamp) VALUES (?, ?, ?)`,
        [userId, `添加预约: ${title}`, Date.now()],
        (logErr) => {
          if (logErr) console.error("记录日志失败:", logErr.message);
        }
      );

      res.status(201).json({ message: "预约成功！" });
    }
  );
});

// 删除预约接口
app.delete("/api/appointments/:id", authenticateToken, (req, res) => {
  const appointmentId = req.params.id;
  const userId = req.user.id;

  db.run(
    `DELETE FROM appointments WHERE id = ? AND user_id = ?`,
    [appointmentId, userId],
    function (err) {
      if (err) return res.status(500).json({ message: "删除预约失败。" });

      db.run(
        `INSERT INTO logs (user_id, message, timestamp) VALUES (?, ?, ?)`,
        [userId, `删除预约 ID: ${appointmentId}`, Date.now()],
        (logErr) => {
          if (logErr) console.error("记录日志失败:", logErr.message);
        }
      );

      res.status(200).json({ message: "预约已删除。" });
    }
  );
});

// 获取日志接口
app.get("/api/logs", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    `SELECT * FROM logs WHERE user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "获取日志失败。" });
      res.status(200).json(rows);
    }
  );
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
