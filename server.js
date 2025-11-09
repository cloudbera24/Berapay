const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/berapay';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    phone: {
        type: String,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    balance: {
        type: Number,
        default: 0
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['deposit', 'withdrawal', 'transfer', 'payment'],
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    reference: {
        type: String,
        required: true,
        unique: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
    },
    phone: {
        type: String,
        required: false
    },
    metadata: {
        type: Object,
        default: {}
    }
}, {
    timestamps: true
});

// Models
const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(verified.id).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'User not found or inactive.'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({
            success: false,
            message: 'Invalid token.'
        });
    }
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'Access denied. Admin privileges required.'
        });
    }
    next();
};

// Generate Reference Number
function generateReference() {
    return 'BP' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
}

// Routes

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

app.get('/admin-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// API Routes

// User Registration
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        // Validation
        if (!name || !email || !phone || !password) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required.'
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long.'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { phone }] 
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or phone already exists.'
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            role: email === 'admin@berapay.com' ? 'admin' : 'user' // Auto-admin for demo
        });

        await user.save();

        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully!',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role,
                balance: user.balance
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error. Please try again.'
        });
    }
});

// User Login
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required.'
            });
        }

        // Check if user exists
        const user = await User.findOne({ email, isActive: true });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role,
                balance: user.balance
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error. Please try again.'
        });
    }
});

// Get User Profile
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                phone: req.user.phone,
                role: req.user.role,
                balance: req.user.balance,
                createdAt: req.user.createdAt
            }
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error.'
        });
    }
});

// Verify Token Endpoint
app.get('/api/users/verify-token', authenticateToken, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role
            }
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({
            success: false,
            message: 'Invalid token.'
        });
    }
});

// Get User Balance
app.get('/api/payments/balance', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json({
            success: true,
            balance: user.balance
        });
    } catch (error) {
        console.error('Balance error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error.'
        });
    }
});

// Get User Transactions
app.get('/api/payments/transactions', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip(skip);

        const total = await Transaction.countDocuments({ userId: req.user._id });

        res.json({
            success: true,
            transactions,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Transactions error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error.'
        });
    }
});

// Simulate STK Push (Deposit)
app.post('/api/payments/stkpush', authenticateToken, async (req, res) => {
    try {
        const { amount, phone, description } = req.body;

        if (!amount || amount < 1) {
            return res.status(400).json({
                success: false,
                message: 'Valid amount is required.'
            });
        }

        // In a real implementation, this would integrate with M-Pesa API
        // For demo purposes, we'll simulate the payment

        const reference = generateReference();
        
        // Create pending transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'deposit',
            amount,
            description: description || 'Wallet Deposit',
            reference,
            status: 'pending',
            phone
        });

        await transaction.save();

        // Simulate payment processing delay
        setTimeout(async () => {
            try {
                // Update transaction status to completed
                transaction.status = 'completed';
                await transaction.save();

                // Update user balance
                await User.findByIdAndUpdate(req.user._id, {
                    $inc: { balance: amount }
                });

                console.log(`Deposit completed: ${amount} for user ${req.user._id}`);
            } catch (error) {
                console.error('Deposit completion error:', error);
            }
        }, 5000); // 5 seconds delay

        res.json({
            success: true,
            message: 'Payment initiated successfully. Check your phone to complete.',
            reference,
            transactionId: transaction._id
        });

    } catch (error) {
        console.error('STK Push error:', error);
        res.status(500).json({
            success: false,
            message: 'Payment initiation failed. Please try again.'
        });
    }
});

// Withdraw Funds
app.post('/api/payments/withdraw', authenticateToken, async (req, res) => {
    try {
        const { amount, phone, description } = req.body;

        if (!amount || amount < 1) {
            return res.status(400).json({
                success: false,
                message: 'Valid amount is required.'
            });
        }

        // Check sufficient balance
        const user = await User.findById(req.user._id);
        if (user.balance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance.'
            });
        }

        const reference = generateReference();
        
        // Create pending transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'withdrawal',
            amount,
            description: description || 'Wallet Withdrawal',
            reference,
            status: 'pending',
            phone
        });

        await transaction.save();

        // Simulate withdrawal processing
        setTimeout(async () => {
            try {
                // Update transaction status to completed
                transaction.status = 'completed';
                await transaction.save();

                // Update user balance
                await User.findByIdAndUpdate(req.user._id, {
                    $inc: { balance: -amount }
                });

                console.log(`Withdrawal completed: ${amount} for user ${req.user._id}`);
            } catch (error) {
                console.error('Withdrawal completion error:', error);
            }
        }, 3000); // 3 seconds delay

        res.json({
            success: true,
            message: 'Withdrawal initiated successfully.',
            reference,
            transactionId: transaction._id
        });

    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Withdrawal failed. Please try again.'
        });
    }
});

// Admin Routes

// Get Admin Summary
app.get('/api/admin/summary', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ role: 'user' });
        const totalMerchants = await User.countDocuments({ role: 'merchant' }); // If you add merchants later
        const totalTransactions = await Transaction.countDocuments();
        
        // Calculate total commission (2% of all transactions)
        const transactions = await Transaction.find({ status: 'completed' });
        const totalAmount = transactions.reduce((sum, txn) => sum + txn.amount, 0);
        const totalCommission = totalAmount * 0.02;
        const platformEarnings = totalCommission;

        // Get recent transactions
        const recentTransactions = await Transaction.find()
            .populate('userId', 'name email')
            .sort({ createdAt: -1 })
            .limit(10);

        res.json({
            success: true,
            summary: {
                totalUsers,
                totalMerchants,
                totalTransactions,
                totalCommission,
                platformEarnings
            },
            recentTransactions
        });
    } catch (error) {
        console.error('Admin summary error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error.'
        });
    }
});

// Get Users List
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const users = await User.find({ role: 'user' })
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip(skip);

        // Get transaction counts for each user
        const usersWithCounts = await Promise.all(
            users.map(async (user) => {
                const transactionCount = await Transaction.countDocuments({ userId: user._id });
                return {
                    ...user.toObject(),
                    transactionCount
                };
            })
        );

        const total = await User.countDocuments({ role: 'user' });

        res.json({
            success: true,
            users: usersWithCounts,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error.'
        });
    }
});

// Create default admin user (for testing)
async function createDefaultAdmin() {
    try {
        const adminExists = await User.findOne({ email: 'admin@berapay.com' });
        if (!adminExists) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash('admin123', salt);
            
            const adminUser = new User({
                name: 'System Administrator',
                email: 'admin@berapay.com',
                phone: '+254700000000',
                password: hashedPassword,
                role: 'admin'
            });
            
            await adminUser.save();
            console.log('Default admin user created: admin@berapay.com / admin123');
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
}

// 404 Handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found.'
    });
});

// Serve static files for all other routes (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error.'
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Login: http://localhost:${PORT}/login`);
    console.log(`Register: http://localhost:${PORT}/register`);
    
    // Create default admin user
    await createDefaultAdmin();
});

module.exports = app;
