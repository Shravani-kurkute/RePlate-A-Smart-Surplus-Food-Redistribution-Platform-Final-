# RePlate Platform - Database Design & Implementation Guide

## Table of Contents
1. [Database Schema](#database-schema)
2. [SQL Table Creation Scripts](#sql-table-creation-scripts)
3. [API Endpoints](#api-endpoints)
4. [Backend Implementation Guide](#backend-implementation-guide)
5. [Security Best Practices](#security-best-practices)

---

## Database Schema

### Overview
The RePlate platform requires the following core tables:
- **users** - Stores all user accounts (consumers, sellers, admins)
- **user_profiles** - Extended profile information
- **restaurants** - Restaurant/seller information
- **food_listings** - Surplus food items listed by restaurants
- **orders** - Customer orders
- **carbon_impact** - Track environmental impact

---

## SQL Table Creation Scripts

### 1. Users Table
```sql
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(15) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    user_role ENUM('consumer', 'seller', 'admin') NOT NULL DEFAULT 'consumer',
    city VARCHAR(100) NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    
    INDEX idx_email (email),
    INDEX idx_phone (phone),
    INDEX idx_user_role (user_role),
    INDEX idx_city (city)
);
```

### 2. User Profiles Table
```sql
CREATE TABLE user_profiles (
    profile_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    profile_image VARCHAR(255),
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    preferred_cuisine TEXT,
    dietary_preferences TEXT,
    notification_enabled BOOLEAN DEFAULT TRUE,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
```

### 3. Restaurants Table
```sql
CREATE TABLE restaurants (
    restaurant_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    restaurant_name VARCHAR(150) NOT NULL,
    business_license VARCHAR(100),
    cuisine_type VARCHAR(100),
    description TEXT,
    address VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    phone VARCHAR(15) NOT NULL,
    opening_time TIME,
    closing_time TIME,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    rating DECIMAL(3, 2) DEFAULT 0.00,
    total_reviews INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_city (city),
    INDEX idx_verified (is_verified),
    INDEX idx_active (is_active)
);
```

### 4. Food Listings Table
```sql
CREATE TABLE food_listings (
    listing_id INT PRIMARY KEY AUTO_INCREMENT,
    restaurant_id INT NOT NULL,
    food_name VARCHAR(150) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    original_price DECIMAL(10, 2) NOT NULL,
    discounted_price DECIMAL(10, 2) NOT NULL,
    quantity_available INT NOT NULL DEFAULT 0,
    expiry_time TIMESTAMP NOT NULL,
    image_url VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(restaurant_id) ON DELETE CASCADE,
    INDEX idx_restaurant (restaurant_id),
    INDEX idx_active (is_active),
    INDEX idx_expiry (expiry_time)
);
```

### 5. Orders Table
```sql
CREATE TABLE orders (
    order_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    restaurant_id INT NOT NULL,
    listing_id INT NOT NULL,
    quantity INT NOT NULL,
    original_price DECIMAL(10, 2) NOT NULL,
    discount_amount DECIMAL(10, 2) NOT NULL,
    final_price DECIMAL(10, 2) NOT NULL,
    order_status ENUM('pending', 'confirmed', 'ready', 'completed', 'cancelled') DEFAULT 'pending',
    payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    payment_method VARCHAR(50),
    pickup_time TIMESTAMP,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(restaurant_id) ON DELETE CASCADE,
    FOREIGN KEY (listing_id) REFERENCES food_listings(listing_id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_restaurant (restaurant_id),
    INDEX idx_status (order_status)
);
```

### 6. Carbon Impact Table
```sql
CREATE TABLE carbon_impact (
    impact_id INT PRIMARY KEY AUTO_INCREMENT,
    order_id INT NOT NULL,
    user_id INT NOT NULL,
    food_saved_kg DECIMAL(10, 2) NOT NULL,
    co2_reduced_kg DECIMAL(10, 2) NOT NULL,
    tree_equivalent DECIMAL(10, 4) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user (user_id)
);
```

### 7. Password Reset Tokens Table
```sql
CREATE TABLE password_reset_tokens (
    token_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user (user_id)
);
```

### 8. Email Verification Tokens Table
```sql
CREATE TABLE email_verification_tokens (
    verification_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user (user_id)
);
```

---

## API Endpoints

### Authentication Endpoints

#### 1. User Registration (Consumer)
```
POST /api/auth/register/consumer
Content-Type: application/json

Request Body:
{
    "fullName": "John Doe",
    "email": "john@example.com",
    "phone": "9876543210",
    "city": "Mumbai",
    "pincode": "400001",
    "password": "SecurePass123"
}

Response (Success):
{
    "success": true,
    "message": "Registration successful. Please verify your email.",
    "userId": 123,
    "verificationEmailSent": true
}

Response (Error):
{
    "success": false,
    "message": "Email already exists",
    "errors": {
        "email": "This email is already registered"
    }
}
```

#### 2. User Login
```
POST /api/auth/login
Content-Type: application/json

Request Body:
{
    "email": "john@example.com",
    "password": "SecurePass123",
    "role": "consumer"
}

Response (Success):
{
    "success": true,
    "message": "Login successful",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "userId": 123,
        "fullName": "John Doe",
        "email": "john@example.com",
        "role": "consumer"
    },
    "redirectUrl": "/user/dashboard"
}

Response (Error):
{
    "success": false,
    "message": "Invalid credentials"
}
```

#### 3. Email Verification
```
GET /api/auth/verify-email?token=xyz123

Response (Success):
{
    "success": true,
    "message": "Email verified successfully"
}
```

#### 4. Password Reset Request
```
POST /api/auth/forgot-password
Content-Type: application/json

Request Body:
{
    "email": "john@example.com"
}

Response (Success):
{
    "success": true,
    "message": "Password reset link sent to your email"
}
```

---

## Backend Implementation Guide

### Technology Stack Recommendations

#### Option 1: Node.js + Express + MySQL
```javascript
// Example: User Registration Endpoint

const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const router = express.Router();

// Database configuration
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'your_password',
    database: 'replate_db',
    waitForConnections: true,
    connectionLimit: 10
});

// Registration endpoint
router.post('/register/consumer', async (req, res) => {
    try {
        const { fullName, email, phone, city, pincode, password } = req.body;
        
        // Validation
        if (!fullName || !email || !phone || !city || !pincode || !password) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }
        
        // Check if email already exists
        const [existingUsers] = await pool.query(
            'SELECT user_id FROM users WHERE email = ?',
            [email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Email already exists',
                errors: { email: 'This email is already registered' }
            });
        }
        
        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Insert user
        const [result] = await pool.query(
            `INSERT INTO users (full_name, email, phone, city, pincode, password_hash, user_role)
             VALUES (?, ?, ?, ?, ?, ?, 'consumer')`,
            [fullName, email, phone, city, pincode, passwordHash]
        );
        
        const userId = result.insertId;
        
        // Create user profile
        await pool.query(
            'INSERT INTO user_profiles (user_id) VALUES (?)',
            [userId]
        );
        
        // Generate verification token
        const verificationToken = jwt.sign(
            { userId, email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Store verification token
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(
            'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            [userId, verificationToken, expiresAt]
        );
        
        // Send verification email
        await sendVerificationEmail(email, fullName, verificationToken);
        
        res.status(201).json({
            success: true,
            message: 'Registration successful. Please verify your email.',
            userId: userId,
            verificationEmailSent: true
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration'
        });
    }
});

// Email verification function
async function sendVerificationEmail(email, name, token) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });
    
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    
    const mailOptions = {
        from: 'RePlate <noreply@replate.com>',
        to: email,
        subject: 'Verify Your RePlate Account',
        html: `
            <h2>Welcome to RePlate, ${name}!</h2>
            <p>Thank you for joining our community in fighting food waste.</p>
            <p>Please click the button below to verify your email address:</p>
            <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #22c55e; color: white; text-decoration: none; border-radius: 8px;">
                Verify Email
            </a>
            <p>Or copy this link: ${verificationUrl}</p>
            <p>This link will expire in 24 hours.</p>
        `
    };
    
    await transporter.sendMail(mailOptions);
}

module.exports = router;
```

#### Option 2: PHP + Laravel + MySQL
```php
<?php
// Example: User Registration Controller

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserProfile;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class RegisterController extends Controller
{
    public function registerConsumer(Request $request)
    {
        // Validation
        $validator = Validator::make($request->all(), [
            'fullName' => 'required|string|min:3|max:100',
            'email' => 'required|email|unique:users,email',
            'phone' => 'required|digits:10',
            'city' => 'required|string|min:2|max:100',
            'pincode' => 'required|digits:6',
            'password' => [
                'required',
                'min:8',
                'regex:/^(?=.*[A-Z])(?=.*\d)/'
            ]
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 400);
        }
        
        try {
            // Create user
            $user = User::create([
                'full_name' => $request->fullName,
                'email' => $request->email,
                'phone' => $request->phone,
                'city' => $request->city,
                'pincode' => $request->pincode,
                'password_hash' => Hash::make($request->password),
                'user_role' => 'consumer'
            ]);
            
            // Create user profile
            UserProfile::create([
                'user_id' => $user->user_id
            ]);
            
            // Generate verification token
            $token = Str::random(64);
            
            // Store verification token
            \DB::table('email_verification_tokens')->insert([
                'user_id' => $user->user_id,
                'token' => $token,
                'expires_at' => now()->addHours(24),
                'created_at' => now()
            ]);
            
            // Send verification email
            Mail::to($user->email)->send(new \App\Mail\VerifyEmail($user, $token));
            
            return response()->json([
                'success' => true,
                'message' => 'Registration successful. Please verify your email.',
                'userId' => $user->user_id,
                'verificationEmailSent' => true
            ], 201);
            
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Server error during registration'
            ], 500);
        }
    }
}
```

---

## Security Best Practices

### 1. Password Security
- **Use bcrypt or Argon2** for password hashing
- **Salt rounds**: Minimum 10 for bcrypt
- **Never store plain text passwords**
- **Enforce strong password policies** (min 8 chars, uppercase, number)

### 2. Input Validation
- **Server-side validation** is mandatory (never trust client-side only)
- **Sanitize all inputs** to prevent SQL injection
- **Use prepared statements** for database queries
- **Validate email format** and uniqueness
- **Validate phone numbers** (exactly 10 digits)
- **Validate pincodes** (exactly 6 digits)

### 3. Authentication
- **JWT tokens** for session management
- **Token expiration**: 24 hours for access tokens
- **Refresh tokens**: 7-30 days
- **HTTPS only** in production
- **Implement rate limiting** on login attempts

### 4. Email Verification
- **24-hour token expiry**
- **One-time use tokens**
- **Cryptographically secure** token generation

### 5. Database Security
- **Use environment variables** for credentials
- **Principle of least privilege** for database users
- **Regular backups**
- **Enable query logging** for audit trails

---

## Environment Variables (.env)

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=replate_db
DB_USER=replate_user
DB_PASSWORD=secure_password_here

# JWT
JWT_SECRET=your_super_secret_jwt_key_min_32_chars
JWT_EXPIRY=24h

# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=noreply@replate.com

# Frontend
FRONTEND_URL=http://localhost:3000

# Server
PORT=5000
NODE_ENV=development
```

---

## Next Steps

1. **Set up MySQL database**
2. **Run SQL scripts** to create tables
3. **Set up backend** (Node.js/Express or PHP/Laravel)
4. **Install dependencies**
5. **Configure environment variables**
6. **Implement API endpoints**
7. **Connect frontend to backend**
8. **Test registration flow**
9. **Implement email verification**
10. **Deploy to production**

---

## Testing Checklist

- [ ] User can register with valid data
- [ ] Duplicate email is rejected
- [ ] Invalid email format is rejected
- [ ] Phone number validation works (10 digits)
- [ ] Pincode validation works (6 digits)
- [ ] Password strength validation works
- [ ] Password mismatch is detected
- [ ] Terms acceptance is required
- [ ] Verification email is sent
- [ ] Email verification link works
- [ ] User can login after verification
- [ ] Role-based redirect works

---

## Support & Documentation

For more information, refer to:
- MySQL Documentation: https://dev.mysql.com/doc/
- Express.js: https://expressjs.com/
- bcrypt: https://www.npmjs.com/package/bcrypt
- JWT: https://jwt.io/
- Nodemailer: https://nodemailer.com/

---

**RePlate** - Fighting food waste, one plate at a time 🌱
