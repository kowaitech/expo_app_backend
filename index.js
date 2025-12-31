require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const port = process.env.PORT || 5600;

app.use(cors());
app.use(express.json());

const { MongoClient, ServerApiVersion } = require("mongodb");

const uri = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const users = client.db("authdb").collection("users");

    // ================= REGISTER =================
    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;

      const existingUser = await users.findOne({ email });
      if (existingUser) {
        return res.status(400).send({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = {
        name,
        email,
        password: hashedPassword,
        createdAt: new Date(),
      };

      await users.insertOne(user);
      res.send({ message: "User registered successfully" });
    });

    // ================= LOGIN =================
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      const user = await users.findOne({ email });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).send({ message: "Invalid password" });
      }

      const token = jwt.sign(
        { id: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.send({
        message: "Login successful",
        token,
        user: {
          name: user.name,
          email: user.email,
        },
      });
    });

    // ================= PROTECTED =================
    app.get("/profile", verifyToken, (req, res) => {
      res.send({
        message: "Protected route accessed",
        user: req.user,
      });
    });

    console.log("Auth server connected to MongoDB");
  } catch (err) {
    console.error(err);
  }
}

run();

// ================= TOKEN MIDDLEWARE =================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: "Token missing" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

app.listen(port, () => {
  console.log("Auth server running on port", port);
});
