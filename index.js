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

// Middleware to verify the token and user role
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Assuming the token is in the format "Bearer <token>"

  if (!token) {
    return res.status(401).json({ message: "Token is missing or invalid." });
  }

  try {
    // Verify and decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Replace with your secret key

    req.user = decoded; // Attach the decoded user info to the request object

    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token." });
  }
};

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
      try {
        const { name, email, password } = req.body;

        // Check if all fields are provided
        if (!name || !email || !password) {
          return res.status(400).json({
            success: false,
            message: "All fields are required",
          });
        }

        // Check if the user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: "User already exists",
          });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the new user object
        const wishlist = []; // Empty array for wishlist
        const cart = [];
        const newUser = {
          name,
          email,
          role: "buyer",
          password: hashedPassword,
          wishlist,
          cart,
        };

        const result = await usersCollection.insertOne(newUser);

        // Respond with success
        res.status(201).json({
          success: true,
          message: "User registered successfully",
        });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({
          success: false,
          message: "An error occurred during registration",
        });
      }
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
        { name: user.name, email: user.email, role: user.role, id: user._id },
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

    // get user
    app.get("/users", async (req, res) => {
      try {
        if (!usersCollection) {
          throw new Error("usersCollection is not initialized");
        }
        const users = await usersCollection.find().toArray();
        if (!users || users.length === 0) {
          console.log("No users found in the database");
        }
        res.status(200).json(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ message: error.message });
      }
    });
    // update user
    app.put("/users/:id", async (req, res) => {
      try {
        const userId = req.params.id;
        const filter = { _id: new ObjectId(userId) }; // Assuming you're using MongoDB ObjectId
        const updatedData = req.body; // Updated data received from the client

        const updateFields = {};
        for (const key in updatedData) {
          if (updatedData.hasOwnProperty(key)) {
            updateFields[key] = updatedData[key];
          }
        }

        const result = await usersCollection.updateOne(filter, {
          $set: updateFields,
        });

        if (result.modifiedCount === 1) {
          // Supply item updated successfully
          res.status(200).json({ message: "User Role updated" });
        } else {
          // No supply item found with the given ID
          res.status(404).json({ message: "User not found" });
        }
      } catch (error) {
        console.error("Error updating User:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // delete user
    app.delete("/users/:id", async (req, res) => {
      const itemId = req.params.id;
      const query = { _id: new ObjectId(itemId) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });
    // get single user

    app.get("/users/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params; // Get the user ID from the URL
        console.log("id", id);
        const { user } = req; // Get the decoded user from the token
        console.log("user", user.id);
        // Check if the user is trying to access their own data or if they have the right permissions
        if (user.id !== id) {
          return res
            .status(403)
            .json({ message: "You are not authorized to view this user" });
        }

        if (!usersCollection) {
          throw new Error("usersCollection is not initialized");
        }

        // Convert the ID to a valid ObjectId if it's not already
        const objectId = new ObjectId(id);

        // Find a user by the given ID
        const foundUser = await usersCollection.findOne({ _id: objectId });

        if (!foundUser) {
          return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json(foundUser);
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: error.message });
      }
    });

    // add to cart

    app.post("/user/cart", async (req, res) => {
      const { id, productId } = req.body; // `id` is the user ID, and `productId` is the product to add

      try {
        // Find the user by ID
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });
        console.log("Found user:", user);

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        const productID = {
          productId: productId,
        };
        // Update the user's cart by adding the new product
        const updatedUser = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $push: { cart: productID } } // `$push` adds the `productId` to the `cart` array
        );

        console.log("Update result:", updatedUser);

        if (updatedUser.modifiedCount === 0) {
          return res.status(500).json({ error: "Failed to update cart" });
        }

        // Respond with success
        res.status(200).json({ message: "Product added to cart successfully" });
      } catch (error) {
        console.error("Error adding product to cart:", error);
        res.status(500).json({ error: "Failed to add product to cart" });
      }
    });
    // get the user cart from user collection

    // add to wishlist
    app.post("/user/wishlist", async (req, res) => {
      const { id, productId } = req.body; // `id` is the user ID, and `productId` is the product to add

      try {
        // Find the user by ID
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });
        console.log("Found user:", user);

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        const productID = {
          productId: productId,
        };
        // Update the user's cart by adding the new product
        const updatedUser = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $push: { wishlist: productID } } // `$push` adds the `productId` to the `cart` array
        );

        console.log("Update result:", updatedUser);

        if (updatedUser.modifiedCount === 0) {
          return res.status(500).json({ error: "Failed to update cart" });
        }

        // Respond with success
        res.status(200).json({ message: "Product added to cart successfully" });
      } catch (error) {
        console.error("Error adding product to cart:", error);
        res.status(500).json({ error: "Failed to add product to cart" });
      }
    });

    // product

    app.get("/products", async (req, res) => {
      const { search, sort, category, brand, id } = req.query;

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

      // If id[] query parameter is present, filter by product IDs
      if (id) {
        // Ensure the query `id[]` is an array
        const productIds = Array.isArray(id) ? id : [id];

        // Convert string IDs to ObjectId (MongoDB requires ObjectId type for querying)
        filters._id = { $in: productIds.map((id) => new ObjectId(id)) };
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

    app.post("/products", async (req, res) => {
      const { image, category, title, amount, description } = req.body;
      const result = await productsCollection.insertOne({
        image,
        category,
        title,
        amount,
        description,
      });
      res.json({
        success: true,
        message: "New supply added successful",
      });
    });

    app.put("/products/:id", async (req, res) => {
      try {
        const itemId = req.params.id;
        const filter = { _id: new ObjectId(itemId) }; // Assuming you're using MongoDB ObjectId
        const updatedData = req.body; // Updated data received from the client

        const updateFields = {};
        for (const key in updatedData) {
          if (updatedData.hasOwnProperty(key)) {
            updateFields[key] = updatedData[key];
          }
        }

        const result = await productsCollection.updateOne(filter, {
          $set: updateFields,
        });

        if (result.modifiedCount === 1) {
          // Supply item updated successfully
          res.status(200).json({ message: "Supply item updated successfully" });
        } else {
          // No supply item found with the given ID
          res.status(404).json({ message: "Supply item not found" });
        }
      } catch (error) {
        console.error("Error updating supply item:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.delete("/products/:id", async (req, res) => {
      const itemId = req.params.id;
      const query = { _id: new ObjectId(itemId) };
      const result = await productsCollection.deleteOne(query);
      res.send(result);
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
