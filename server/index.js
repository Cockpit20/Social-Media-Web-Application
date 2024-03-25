const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const userRoute = require("./routes/users"); //"./routes/users"
const authRoute = require("./routes/auth");
const postRoute = require("./routes/posts");
const multer = require("multer");
const path = require("path");
const cors = require("cors");

dotenv.config();
mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true }, () => {
    console.log("Mongo Connected")
});
app.use("/images", express.static(path.join(__dirname, "public/images")));


console.log(mongoose.connection.readyState);
app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/images");
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (res, req) => {
    try {
        //return res.status(200).json("file uploaded");
    }
    catch (err) {
        console.log(err);
    }
});

app.use("/api/users", userRoute);
app.use("/api/auth", authRoute);
app.use("/api/posts", postRoute);


app.get("/", (req, res) => {
    res.send("Welcome to homepage")
})

const User = require("../server/models/User");
const bcrypt = require("bcryptjs");

app.post("/auth/register", async (req, res) => {
    try {
        //generate new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        //create new user
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
        });

        //save user and respond
        const user = await newUser.save();
        res.status(200).json(user);
    } catch (err) {
        res.status(500).json(err)
        console.log(err);
    }
})

app.post("/auth/login", async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            res.status(404).json("user not found");
        }

        else if (await bcrypt.compare(req.body.password, user.password) == false)
            res.status(400).json("wrong password")

        else {
            res.status(200).json(user)
        }
    }

    catch (err) {
        console.log(err)
        res.status(500).json(err)
    }
});

app.listen(process.env.PORT || 3000, () => {
    console.log("Backend Server initiated")
})