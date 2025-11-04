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
mongoose
  .connect(
    process.env.MONGODB_URI ||
      "mongodb+srv://dpdp8311:dpdp8311@cluster0.5ysqydm.mongodb.net/Template"
  )
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
const MenuSchema = new mongoose.Schema({
  path: String,
  name: String,
  icon: String,
  layout: String,
  enabled: { type: Boolean, default: true }
});
const Users = mongoose.model("Users", UserSchema);
const Menus = mongoose.model("Menus", MenuSchema);



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

app.get("/menus", authenticateToken, async (req, res) => {
  try {
    const menus = await Menus.find({ enabled: true });
    res.json(menus);
  } catch (error) {
    res.status(500).json({ message: "Error fetching menus", error: error.message });
  }
});

app.get("/all-menus", authenticateToken, async (req, res) => {
  try {
    const menus = await Menus.find({});
    res.json(menus);
  } catch (error) {
    res.status(500).json({ message: "Error fetching menus", error: error.message });
  }
});

app.put("/toggle-menu/:id", authenticateToken, async (req, res) => {
  try {
    const menu = await Menus.findById(req.params.id);
    if (!menu) {
      return res.status(404).json({ message: "Menu not found" });
    }
    menu.enabled = !menu.enabled;
    await menu.save();
    res.json({ message: "Menu status updated", enabled: menu.enabled });
  } catch (error) {
    res.status(500).json({ message: "Error updating menu", error: error.message });
  }
});

app.get("/menunames", authenticateToken, async (req, res) => {
  try {
    const menus = await Menus.find({}).select('name -_id');
    res.json(menus);
  }
  catch (error) {
    res.status(500).json({ message: "Error fetching menus", error: error.message });
  }
});

app.post("/add-menu",  async (req, res) => {
  try {
    const existingMenu = await Menus.findOne({ path: "/menus" });
    if (!existingMenu) {
      await Menus.create({
        path: "/menus",
        name: "Menus",
        icon: "nc-icon nc-bullet-list-67",
        layout: "/admin"
      });
      res.json({ message: "Menus option added successfully" });
    } else {
      res.json({ message: "Menus option already exists" });
    }
  } catch (error) {
    res.status(500).json({ message: "Error adding menu", error: error.message });
  }
});




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