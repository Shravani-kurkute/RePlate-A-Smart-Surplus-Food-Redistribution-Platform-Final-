const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();

app.use(cors());
app.use(express.json());

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  const { fullName, email, phone, city, pincode, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users (fullName, email, phone, city, pincode, password)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [fullName, email, phone, city, pincode, hashedPassword],
      (err) => {
        if (err) {
          return res.status(400).json({ msg: "Email already exists" });
        }

        res.json({ msg: "User registered successfully" });
      }
    );
  } catch (error) {
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const user = results[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    res.json({
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email
      }
    });
  });
});

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000 🚀");
});


/* ================= SELLER REGISTER ================= */
app.post("/seller-register", async (req, res) => {
  const {
    businessName,
    ownerName,
    businessType,
    gstNumber,
    fssaiNumber,
    email,
    phone,
    address,
    city,
    pincode,
    password
  } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO sellers 
      (businessName, ownerName, businessType, gstNumber, fssaiNumber, email, phone, address, city, pincode, password)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(sql, [
      businessName,
      ownerName,
      businessType,
      gstNumber,
      fssaiNumber,
      email,
      phone,
      address,
      city,
      pincode,
      hashedPassword
    ], (err) => {
      if (err) {
        return res.status(400).json({ msg: "Email already exists" });
      }

      res.json({ msg: "Seller registered successfully" });
    });

  } catch (error) {
    res.status(500).json({ msg: "Server error" });
  }
});


/* ================= SELLER LOGIN ================= */
app.post("/seller-login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM sellers WHERE email = ?";

  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const seller = results[0];

    const isMatch = await bcrypt.compare(password, seller.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    res.json({
      seller: {
        id: seller.id,
        businessName: seller.businessName,
        email: seller.email,
        status: seller.status
      }
    });
  });
});

app.post("/add-listing", (req, res) => {
  const {
    seller_id,
    foodName,
    category,
    description,
    image,
    originalPrice,
    discountPercent,
    finalPrice,
    quantity,
    weight,
    manufacturingDate,
    expiryDate,
    expiryTime
  } = req.body;

  const sql = `
    INSERT INTO listings
    (seller_id, foodName, category, description, image,
     originalPrice, discountPercent, finalPrice, quantity,
     weight, manufacturingDate, expiryDate, expiryTime)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [
    seller_id,
    foodName,
    category,
    description,
    image,
    originalPrice,
    discountPercent,
    finalPrice,
    quantity,
    weight,
    manufacturingDate,
    expiryDate,
    expiryTime
  ], (err) => {
    if (err) return res.status(500).json({ msg: "Error adding listing" });
    res.json({ msg: "Listing added successfully" });
  });
});

app.get("/seller-listings/:sellerId", (req, res) => {
  const sql = "SELECT * FROM listings WHERE seller_id = ?";
  db.query(sql, [req.params.sellerId], (err, results) => {
    if (err) return res.status(500).json({ msg: "Error fetching listings" });
    res.json(results);
  });
});

app.get("/marketplace", (req, res) => {
  const sql = `
    SELECT listings.*, sellers.businessName 
    FROM listings
    JOIN sellers ON listings.seller_id = sellers.id
    WHERE listings.status = 'active'
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ msg: "Error fetching marketplace" });
    res.json(results);
  });
});

