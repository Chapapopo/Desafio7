import mongoose from "mongoose";

const uri = "mongodb+srv://darma01ps:Overdriver58@cluster0.1mmnhkv.mongodb.net/ecommerce";

mongoose.connect(uri,/*  { useNewUrlParser: true, useUnifiedTopology: true } */)
  .catch(err => console.error(err));

const db = mongoose.connection;

db.once("open", _ => {
  console.log("Database is connected to:", uri);
});

db.on("error", err => {
  console.error("Database connection error:", err);
});