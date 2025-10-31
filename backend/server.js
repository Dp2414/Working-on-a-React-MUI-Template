const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express(); 
const port = 5000;
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/Template")
.then(() => {
  console.log("Connected to MongoDB");
})
.catch((error) => {
  console.error("Error connecting to MongoDB:", error);
});
const UserSchema= new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});
const Users = mongoose.model("Users", UserSchema);



// app.get('/getmenus', (req,res))

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }
  
  jwt.verify(token, "secretkey", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Verify token route
app.get('/verify', authenticateToken, async (req, res) => {
  try {
    const user = await Users.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/signup', async(req, res) => {
    try {
        const { name, email, password } = req.body;
        
        const existingUser = await Users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new Users({ name, email, password: hashedPassword });
        await user.save();
        
        const token = jwt.sign({ userId: user._id, email: user.email }, "secretkey", { expiresIn: "24h" });
        
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.status(201).json({
            message: "User created successfully",
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }
        
        const token = jwt.sign({ userId: user._id, email: user.email }, "secretkey", { expiresIn: "24h" });
        
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({
            message: "Login successful",
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
})

app.post("/logout", authenticateToken, async (req, res) => {
  res.clearCookie('token');
  res.json({ message: "Logout successful" });
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});