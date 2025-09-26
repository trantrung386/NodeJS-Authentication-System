import mongoose from "mongoose";
import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import { transporter } from "../config/nodemailerConfig.js";
import dotenv from "dotenv";
import fetch from "node-fetch"; // dùng để verify reCAPTCHA

dotenv.config();

export class UserGetController {
    // SIGN UP PAGE
    getSignUpPage = (req, res) => {
        res.render("signup", { 
            message: "", 
            siteKey: process.env.RECAPTCHA_SITE_KEY 
        });
    };

    // SIGN IN PAGE
    getSignInPage = (req, res) => {
        res.render("signin", { 
            message: "", 
            siteKey: process.env.RECAPTCHA_SITE_KEY 
        });
    };

    // HOMEPAGE
    homePage = (req, res) => {
        const email = req.session.userEmail;
        if (!email) {
            return res.status(401).render("signin", { 
                message: "Please sign in to view the homepage",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }
        res.render("homepage");
    };

    // FORGOT PASSWORD PAGE
    getForgotPassword = (req, res) => {
        res.render("forgot-password", { message: "" });
    };

    // CHANGE PASSWORD PAGE
    // CHANGE PASSWORD PAGE
getChangePassword = (req, res) => {
    const email = req.session.userEmail;
    if (!email) {
        return res.status(401).render("signin", { 
            message: "Please sign in to change the password",
            siteKey: process.env.RECAPTCHA_SITE_KEY
        });
    }
    res.render("change-password", { 
        message: "", 
        siteKey: process.env.RECAPTCHA_SITE_KEY 
    });
};

    // LOGOUT
    logoutUser = (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                console.error("Error signing out:", err);
                res.status(500).send("Error signing out");
            } else {
                res.redirect("/user/signin");
            }
        });
    };
}

export class UserPostController {
    // SIGN UP
    createUser = async (req, res) => {
        const { username, email, password, cpassword } = req.body;

        if (password !== cpassword) {
            return res.status(400).render("signup", { 
                message: "Passwords don't match", 
                siteKey: process.env.RECAPTCHA_SITE_KEY 
            });
        }

        try {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).render("signup", { 
                    message: "User already exists",
                    siteKey: process.env.RECAPTCHA_SITE_KEY
                });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({ username, email, password: hashedPassword });

            await newUser.save();
            res.status(201).render("signin", { 
                message: "User created successfully. Please sign in.",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        } catch (error) {
            res.status(500).render("signup", { 
                message: error.message, 
                siteKey: process.env.RECAPTCHA_SITE_KEY 
            });
        }
    };

    // SIGN IN + reCAPTCHA
    signInUser = async (req, res) => {
        const { email, password } = req.body;
        const recaptcha = req.body["g-recaptcha-response"];

        if (!recaptcha) {
            return res.status(400).render("signin", { 
                message: "Please complete captcha",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }

        try {
            // Verify reCAPTCHA với Google
            const secretKey = process.env.RECAPTCHA_SECRET_KEY;
            const captchaRes = await fetch("https://www.google.com/recaptcha/api/siteverify", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `secret=${secretKey}&response=${recaptcha}`
            });
            const captchaData = await captchaRes.json();

            if (!captchaData.success) {
                return res.status(400).render("signin", { 
                    message: "Captcha verification failed",
                    siteKey: process.env.RECAPTCHA_SITE_KEY
                });
            }

            // Check user tồn tại
            const existingUser = await User.findOne({ email });
            if (!existingUser) {
                return res.status(404).render("signin", { 
                    message: "User doesn't exist",
                    siteKey: process.env.RECAPTCHA_SITE_KEY
                });
            }

            // Check password
            const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
            if (!isPasswordCorrect) {
                return res.status(400).render("signin", { 
                    message: "Invalid credentials || Incorrect Password",
                    siteKey: process.env.RECAPTCHA_SITE_KEY
                });
            }

            req.session.userEmail = email;
            res.redirect("/user/homepage");
        } catch (error) {
            res.status(500).render("signin", { 
                message: error.message,
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }
    };

    // FORGOT PASSWORD
    forgotPassword = async (req, res) => {
        const { email } = req.body;

        try {
            const existingUser = await User.findOne({ email });
            if (!existingUser) {
                return res.status(404).render("forgot-password", { message: "User doesn't exist" });
            }

            const newPassword = Math.random().toString(36).slice(-8);
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            try {
                await transporter.sendMail({
                    from: process.env.EMAIL,
                    to: email,
                    subject: "Password Reset",
                    text: `Your new password is: ${newPassword}`,
                });
            } catch (mailError) {
                console.error("Email error:", mailError);
                return res.status(500).render("forgot-password", { message: "Failed to send email. Try again." });
            }

            existingUser.password = hashedPassword;
            await existingUser.save();

            res.status(200).render("signin", { 
                message: "New password sent to your email",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        } catch (error) {
            res.status(500).render("forgot-password", { message: error.message });
        }
    };

    // CHANGE PASSWORD
    changePassword = async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    try {
        const email = req.session.userEmail;
        if (!email) {
            return res.status(401).render("signin", { 
                message: "Please sign in to change your password.",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).render("change-password", { 
                message: "User doesn't exist",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }

        const isPasswordCorrect = await bcrypt.compare(oldPassword, existingUser.password);
        if (!isPasswordCorrect) {
            return res.status(400).render("change-password", { 
                message: "Old password is incorrect",
                siteKey: process.env.RECAPTCHA_SITE_KEY
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        existingUser.password = hashedPassword;
        await existingUser.save();

        // Sau khi đổi mật khẩu thì xoá session để bắt buộc đăng nhập lại
        req.session.destroy((err) => {
            if (err) console.error("Session destroy error:", err);
        });

        res.status(200).render("signin", { 
            message: "Password changed successfully. Please sign in again.",
            siteKey: process.env.RECAPTCHA_SITE_KEY
        });
    } catch (error) {
        res.status(500).render("change-password", { 
            message: "Something went wrong: " + error.message,
            siteKey: process.env.RECAPTCHA_SITE_KEY
        });
    }
};

};


