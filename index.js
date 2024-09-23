import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import passport from "passport";
import login from "./auth.js";
import pool from "./db.js";
import env from "dotenv";
import session from "express-session";

env.config();

const saltRounds = parseInt(process.env.SALT_ROUNDS);
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 跨域請求
// server端port設定5000
// react預設port是3000
// 若都設3000會有port衝突問題(重複使用)
// 因此在server端要設定corsOptions，並用cors開通
const corsOptions = {
  origin: ["http://localhost:3000"],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
  c: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());
pool.connect();

// ROUTES
// Auth
app.get("/", passport.authenticate("token", { session: false }), (req, res) => {
  res.json(req.user);
});
// login
app.post("/login", passport.authenticate("login", { session: false }), login);
// logout
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.json("Log Out Success!");
  });
});
// create a account
app.post("/register", async (req, res) => {
  console.log(saltRounds);

  try {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    console.log(name, email, password);

    const checkResult = await pool.query(
      "SELECT * FROM userdata WHERE email = $1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      res
        .status(200)
        .json({ message: "Email already exists. Try logging in!" });
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.status(401).json({ message: "Error!" });
        } else {
          // console.log("Hashed Password:", hash);
          const newUser = await pool.query(
            "INSERT INTO userdata (name, email, password) VALUES($1,$2,$3) RETURNING *",
            [name, email, hash]
          );
          res.status(200).json({ message: "Success. Try logging in!" });
        }
      });
    }
  } catch (err) {
    console.error(err.message);
  }
});

// get stock list
app.get(
  "/stock_list",
  passport.authenticate("stocklist", { session: false }),
  (req, res) => {
    res.json(req.user);
  }
);

app.post("/buyin", (req, res, next) => {
  passport.authenticate(
    "token",
    { session: false },
    async (err, user, info) => {
      if (err) {
        console.log(err);
      }
      if (info != undefined) {
        console.log(info.message);
        res.send(info.message);
      } else {
        try {
          const ID = req.body.stockID;
          const stock_name = req.body.name;
          const amount = parseInt(req.body.amount);
          const price = parseFloat(req.body.price).toFixed(2);
          const userID = user.user_id;
          const checkResult = await pool.query(
            "SELECT * FROM stocklist JOIN userdata ON userdata.user_id=stocklist.user_id WHERE stocklist.stock_id = $1 AND userdata.user_id = $2",
            [ID, userID]
          );
          if (checkResult.rows.length > 0) {
            try {
              const holdamount = checkResult.rows[0].stock_hold + amount;
              const holdcost = (
                (checkResult.rows[0].stock_hold *
                  checkResult.rows[0].stock_cost +
                  amount * price) /
                holdamount
              ).toFixed(2);
              const updatestock = await pool.query(
                "UPDATE stocklist SET stock_hold = $1, stock_cost = $2 WHERE stocklist.stock_id = $3 AND stocklist.user_id = $4",
                [holdamount, holdcost, ID, userID]
              );
              res.status(200).json({ message: "UpDate Success!" });
            } catch (error) {
              console.error(err.message);
            }
          } else if (checkResult.rows.length === 0) {
            const newstock = await pool.query(
              "INSERT INTO stocklist (stock_id,stock_name,stock_hold,stock_cost,user_id) VALUES($1,$2,$3,$4,$5) RETURNING *",
              [ID, stock_name, amount, price, userID]
            );
            res.status(200).json({ message: "Stock Add Success!" });
          }
        } catch (error) {
          console.error(err.message);
        }
      }
    }
  )(req, res, next);
});

app.post("/sell", (req, res, next) => {
  passport.authenticate(
    "token",
    { session: false },
    async (err, user, info) => {
      if (err) {
        console.log(err);
      }
      if (info != undefined) {
        console.log(info.message);
        res.send(info.message);
      } else {
        try {
          const ID = req.body.stockID;
          const amount = parseInt(req.body.amount);
          const price = parseFloat(req.body.price).toFixed(2);
          const userID = user.user_id;
          const checkResult = await pool.query(
            "SELECT * FROM stocklist JOIN userdata ON userdata.user_id=stocklist.user_id WHERE stocklist.stock_id = $1 AND userdata.user_id = $2",
            [ID, userID]
          );

          if (checkResult.rows.length > 0) {
            const holdamount = checkResult.rows[0].stock_hold - amount;
            if (holdamount > 0) {
              try {
                const updatestock = await pool.query(
                  "UPDATE stocklist SET stock_hold = $1 WHERE stocklist.stock_id = $2 AND stocklist.user_id = $3",
                  [holdamount, ID, userID]
                );
                res.status(200).json({ message: "UpDate Success!" });
              } catch (error) {
                console.error(err.message);
              }
            } else if (holdamount === 0) {
              try {
                const updatestock = await pool.query(
                  "DELETE FROM stocklist WHERE stock_id = $1 AND user_id =$2",
                  [ID, userID]
                );
                res.status(200).json({ message: "UpDate Success!" });
              } catch (error) {
                console.error(err.message);
              }
            } else {
              res.status(200).json({ message: "Insufficient stock!" });
            }
          } else if (checkResult.rows.length === 0) {
            res.status(200).json({ message: "Non-held stocks!" });
          }
        } catch (error) {
          console.error(err.message);
        }
      }
    }
  )(req, res, next);
});

app.listen(5000, () => {
  console.log("sever has started on port 5000");
});
