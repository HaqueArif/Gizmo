const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 4000;

// middleware
app.use(cors());
app.use(express.json());

// mongodb

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("gizmoGalaxy");
    const usersCollection = db.collection("users");
    const productsCollection = db.collection("products");

    // User Registration
    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;
      console.log(req.body);
      // Check if email already exists
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "User already exists",
        });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user into the database
      await usersCollection.insertOne({
        name,
        email,
        role: "buyer",
        password: hashedPassword,
      });

      res.status(201).json({
        success: true,
        message: "User registered successfully",
      });
    });
    // User Login
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      // Find user by email
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      // Compare hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      // Generate JWT token
      const token = jwt.sign(
        { name: user.name, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.EXPIRES_IN,
        }
      );

      res.json({
        success: true,
        message: "Login successful",
        token,
      });
    });

    // product

    app.get("/products", async (req, res) => {
      const { search, sort, category, brand } = req.query;

      // Initialize an empty filter object
      const filters = {};

      // Handle search query (case-insensitive search for product name)
      if (search) {
        filters.name = { $regex: search, $options: "i" }; // Matches any part of the name
      }

      // Handle category filter
      if (category) {
        filters.category = category;
      }

      // Handle brand filter
      if (brand) {
        filters.brand = brand;
      }

      // MongoDB query to find matching products
      try {
        let query = productsCollection.find(filters); // Apply filters to the MongoDB query

        // Sorting: If 'sort' query parameter is provided
        if (sort) {
          if (sort === "price-asc") {
            query = query.sort({ price: 1 }); // Ascending price
          } else if (sort === "price-desc") {
            query = query.sort({ price: -1 }); // Descending price
          }
        }

        // Execute the query and return the results
        const result = await query.toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching products:", error);
        res.status(500).json({ message: "Error fetching products" });
      }
    });

    app.get("/products/:id", async (req, res) => {
      const { id } = req.params;
      console.log("Request received for product ID:", id);

      if (!ObjectId.isValid(id)) {
        console.log("Invalid ID format:", id);
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const product = await productsCollection.findOne({
          _id: new ObjectId(id),
        });
        console.log("Product fetched:", product);

        if (!product) {
          console.log("Product not found for ID:", id);
          return res.status(404).json({ message: "Product not found" });
        }

        res.json(product);
      } catch (error) {
        console.error("Error fetching product by ID:", error);
        res
          .status(500)
          .json({ message: "An error occurred while fetching the product" });
      }
    });

    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } finally {
  }
}

run().catch(console.dir);

// api
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running smoothly",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});
