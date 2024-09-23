import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import passport from 'passport';
import passportJWT from 'passport-jwt';
import {Strategy} from 'passport-local';
import pool from './db.js';
import env from 'dotenv';

env.config()

const JWTStrategy   = passportJWT.Strategy
const extractJWT    = passportJWT.ExtractJwt

// env
const secret_key    = process.env.SECRET_KEY;

const resData = {
    user_id:0,
    name:'',
    email:'',
    token:''
}

pool.connect();

passport.use("login",
  new Strategy({
    // 由於client端是用email+password，所以需要外定義，若為username+password則不用 
    usernameField: 'email',
    passportField: 'password',
    passReqToCallback: true, // 如果需要在 verify callback 中取得 req
  },
  async function verify(req,email, password, done) {
    try {
      const result = await pool.query("SELECT * FROM userdata WHERE email = $1 ", [
        email,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return done(err, false);
          } else {
            if (valid) {
              //Passed password check
              return done(null, user);
            } else {
              //Did not pass password check
              return done(null,{ message: 'Incorrect password.' });
            }
          }
        });
      } else {
        return done(null,{ message: 'Incorrect username.'});
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use('token', new JWTStrategy({
  jwtFromRequest: extractJWT.fromAuthHeaderAsBearerToken('Authorization'),
  secretOrKey: secret_key},
  async (jwtPayload, done) => {
    try { const result = await pool.query("SELECT * FROM userdata WHERE user_id = $1 ", [jwtPayload.user_id]);
      const user = result.rows[0];
      if (result.rows.length > 0) {
        return done(null,user)
      } else {
        return done(null,false)
      }
    } catch (err) {
      done(err)
    }
}))

passport.use('stocklist', new JWTStrategy({
  jwtFromRequest: extractJWT.fromAuthHeaderAsBearerToken('Authorization'),
  secretOrKey: secret_key},
  async (jwtPayload, done) => {
    try { const result = await pool.query("SELECT * FROM userdata JOIN stocklist ON userdata.user_id=stocklist.user_id WHERE userdata.user_id = $1 ", [jwtPayload.user_id]);
      const data = result.rows;
      if(data){
        const dataOutPut = data.map((info)=>{
          const r = {
            user_id:info.user_id,
            stock_id:info.stock_id,
            stock_name:info.stock_name,
            stock_cost:info.stock_cost,
            stock_hold:info.stock_hold,
          }
          return r
        })
        return done(null,dataOutPut)
      } else {
        return done(null,false)
      }
    } catch (err) {
      done(err)
    }
  }))

const signinMW = (req, res) => {
  if (req.user.message){
    res.json(req.user)
  } else {
    resData.email = req.user.email;
    resData.user_id = req.user.user_id;
    resData.name = req.user.name;
    resData.token = jwt.sign(req.user, secret_key,{ expiresIn: 60*30 })
    res.json(resData)
  }
}

export default signinMW
