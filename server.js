const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { newEnforcer } = require('casbin');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.static('public'));

// Database simulation with JSON files
const DB_PATH = './data';
const USERS_FILE = path.join(DB_PATH, 'users.json');
const ROLES_FILE = path.join(DB_PATH, 'roles.json');
const PERMISSIONS_FILE = path.join(DB_PATH, 'permissions.json');
const REPORTS_FILE = path.join(DB_PATH, 'reports.json');

// Initialize data directory and files
async function initializeDB() {
    try {
        await fs.mkdir(DB_PATH, { recursive: true });
        
        // Initialize users
        try {
            await fs.access(USERS_FILE);
        } catch {
            const defaultUsers = [
                {
                    id: 1,
                    username: 'admin',
                    email: 'admin@example.com',
                    password: await bcrypt.hash('admin123', 10),
                    roles: ['admin'],
                    createdAt: new Date().toISOString()
                },
                {
                    id: 2,
                    username: 'user',
                    email: 'user@example.com',
                    password: await bcrypt.hash('user123', 10),
                    roles: ['user'],
                    createdAt: new Date().toISOString()
                },
                {
                    id: 3,
                    username: 'manager',
                    email: 'manager@example.com',
                    password: await bcrypt.hash('manager123', 10),
                    roles: ['manager'],
                    createdAt: new Date().toISOString()
                }
            ];
            await fs.writeFile(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
        }

        // Initialize roles
        try {
            await fs.access(ROLES_FILE);
        } catch {
            const defaultRoles = [
                { id: 1, name: 'admin', description: 'Administrator with full access' },
                { id: 2, name: 'manager', description: 'Manager with limited admin access' },
                { id: 3, name: 'user', description: 'Regular user with basic access' }
            ];
            await fs.writeFile(ROLES_FILE, JSON.stringify(defaultRoles, null, 2));
        }

        // Initialize sample reports data
        try {
            await fs.access(REPORTS_FILE);
        } catch {
            const sampleReports = [
                { id: 1, title: 'Sales Report Q1', data: [
                    { month: 'Jan', sales: 10000, region: 'North' },
                    { month: 'Feb', sales: 12000, region: 'North' },
                    { month: 'Mar', sales: 15000, region: 'North' }
                ]},
                { id: 2, title: 'User Analytics', data: [
                    { date: '2024-01-01', users: 150, sessions: 300 },
                    { date: '2024-01-02', users: 180, sessions: 360 },
                    { date: '2024-01-03', users: 200, sessions: 420 }
                ]}
            ];
            await fs.writeFile(REPORTS_FILE, JSON.stringify(sampleReports, null, 2));
        }

    } catch (error) {
        console.error('Error initializing database:', error);
    }
}

// Casbin configuration
let enforcer;
async function initializeCasbin() {
    try {
        // Create model file
        const modelConf = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
        `;
        
        await fs.writeFile('./model.conf', modelConf.trim());

        // Create policy file
        const policyCSV = `
p, admin, users, read
p, admin, users, write
p, admin, users, delete
p, admin, reports, read
p, admin, reports, write
p, admin, reports, delete
p, admin, roles, read
p, admin, roles, write
p, manager, users, read
p, manager, reports, read
p, manager, reports, write
p, user, reports, readx
        `;
        
        await fs.writeFile('./policy.csv', policyCSV.trim());
        
        enforcer = await newEnforcer('./model.conf', './policy.csv');
        console.log('Casbin enforcer initialized');
    } catch (error) {
        console.error('Error initializing Casbin:', error);
    }
}

// Database helper functions
async function readJSONFile(filepath) {
    try {
        const data = await fs.readFile(filepath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

async function writeJSONFile(filepath, data) {
    await fs.writeFile(filepath, JSON.stringify(data, null, 2));
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Authorization middleware
const authorize = (resource, action) => {
    return async (req, res, next) => {
        if (!enforcer) {
            return res.status(500).json({ error: 'Authorization system not initialized' });
        }

        const userRoles = req.user.roles || [];
        let hasPermission = false;

        for (const role of userRoles) {
            if (await enforcer.enforce(role, resource, action)) {
                hasPermission = true;
                break;
            }
        }

        if (!hasPermission) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
    };
};

// Auth routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = await readJSONFile(USERS_FILE);
        
        const user = users.find(u => u.username === username);
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, roles: user.roles },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                roles: user.roles
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        roles: req.user.roles
    });
});

// User management routes
app.get('/api/users', authenticateToken, authorize('users', 'read'), async (req, res) => {
    try {
        const users = await readJSONFile(USERS_FILE);
        const safeUsers = users.map(({ password, ...user }) => user);
        res.json(safeUsers);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/users', authenticateToken, authorize('users', 'write'), async (req, res) => {
    try {
        const { username, email, password, roles } = req.body;
        const users = await readJSONFile(USERS_FILE);
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Math.max(...users.map(u => u.id), 0) + 1,
            username,
            email,
            password: hashedPassword,
            roles: roles || ['user'],
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        await writeJSONFile(USERS_FILE, users);
        
        const { password: _, ...safeUser } = newUser;
        res.status(201).json(safeUser);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.delete('/api/users/:id', authenticateToken, authorize('users', 'delete'), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const users = await readJSONFile(USERS_FILE);
        
        const filteredUsers = users.filter(u => u.id !== userId);
        await writeJSONFile(USERS_FILE, filteredUsers);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Reports routes
app.get('/api/reports', authenticateToken, authorize('reports', 'read'), async (req, res) => {
    try {
        const reports = await readJSONFile(REPORTS_FILE);
        res.json(reports);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

app.post('/api/reports', authenticateToken, authorize('reports', 'write'), async (req, res) => {
    try {
        const { title, data } = req.body;
        const reports = await readJSONFile(REPORTS_FILE);
        
        const newReport = {
            id: Math.max(...reports.map(r => r.id), 0) + 1,
            title,
            data,
            createdAt: new Date().toISOString(),
            createdBy: req.user.username
        };

        reports.push(newReport);
        await writeJSONFile(REPORTS_FILE, reports);
        
        res.status(201).json(newReport);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create report' });
    }
});

// Roles routes
app.get('/api/roles', authenticateToken, authorize('roles', 'read'), async (req, res) => {
    try {
        const roles = await readJSONFile(ROLES_FILE);
        res.json(roles);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch roles' });
    }
});

// Permissions check endpoint
app.post('/api/permissions/check', authenticateToken, async (req, res) => {
    try {
        const { resource, action } = req.body;
        const userRoles = req.user.roles || [];
        let hasPermission = false;

        for (const role of userRoles) {
            if (await enforcer.enforce(role, resource, action)) {
                hasPermission = true;
                break;
            }
        }

        res.json({ hasPermission });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check permissions' });
    }
});

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize and start server
async function startServer() {
    await initializeDB();
    await initializeCasbin();
    
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

startServer().catch(console.error);