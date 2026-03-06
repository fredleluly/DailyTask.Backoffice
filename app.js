/**
 * app.js — Daily Tracker v2 (SECURITY IMPROVED)
 * Multi-level, multi-tenant daily report system
 */
const express = require('express');
const { Pool } = require('pg');
const cookieSession = require('cookie-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const argon2 = require('argon2');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const ExcelJS = require('exceljs');
const PDFDocument = require('pdfkit');
const helmet = require('helmet');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const https = require('https');

// ── REAL-TIME HELPER ──
// Fetches actual Unix time from worldtimeapi to work around the server's
// clock being set to 2026, which breaks TOTP validation.
function getRealTime() {
    return new Promise((resolve) => {
        const req = https.get('https://worldtimeapi.org/api/timezone/Asia/Jakarta', (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    // unixtime is seconds since epoch
                    resolve(json.unixtime || Math.floor(Date.now() / 1000));
                } catch {
                    resolve(Math.floor(Date.now() / 1000));
                }
            });
        });
        req.on('error', () => resolve(Math.floor(Date.now() / 1000)));
        req.setTimeout(3000, () => { req.destroy(); resolve(Math.floor(Date.now() / 1000)); });
    });
}
require('dotenv').config();
process.env.TZ = 'Asia/Jakarta';

const { isAuth, authorize, auditLog, isDirectorAuth, authorizeDirector, isAnyAuth } = require('./middleware/auth');

const app = express();
app.set('trust proxy', 1); // Mengizinkan pembacaan IP di belakang proxy (Nginx/Cloudflare)


// ─── DATABASE ─────────────────────────────────────────────────────────────────
// Aiven PostgreSQL membutuhkan SSL; gunakan ca.pem untuk verifikasi sertifikat
const poolConfig = {
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    max: parseInt(process.env.DB_POOL_MAX, 10) || 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
};

// Aktifkan SSL jika ca.pem ada (wajib untuk Aiven Cloud)
const caPath = path.join(__dirname, 'ca.pem');
if (fs.existsSync(caPath)) {
    poolConfig.ssl = {
        rejectUnauthorized: true,
        ca: fs.readFileSync(caPath).toString(),
    };
}

const pool = new Pool(poolConfig);

// ─── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Helmet Security Headers
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Session: cookie-session (works on Vercel/serverless, no DB/Redis needed, no connect-pg-simple)
app.use(cookieSession({
    name: 'session',
    secret: process.env.SESSION_SECRET || 'dailytracker_secret_v2_2026',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
}));

// Audit log middleware
app.use(auditLog(pool));

// Rate limiting login endpoint (Tingkatkan batas agar user normal tidak mudah terblokir)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // Tingkatkan dari 10 ke 100 percobaan per 15 menit
    message: 'Terlalu banyak percobaan login, coba lagi dalam 15 menit.',
});

// Rate limiting MFA verification (Tingkatkan batas dari 5 ke 50)
const mfaLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: 'Terlalu banyak percobaan verifikasi, coba lagi dalam 15 menit.',
    keyGenerator: (req) => req.session.tempUser?.id || req.ip,
});


// ─── FILE UPLOAD ───────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowed = ['.pdf', '.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Hanya file PDF, JPG, dan PNG yang diizinkan'), false);
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 }
});

// ─── HELPER FUNCTIONS ──────────────────────────────────────────────────────────

const FINANCE_DEPTS = ['Sales', 'Marketing', 'Finance', 'Purchasing'];

function isFinanceDept(deptName) {
    return ['sales', 'marketing', 'finance', 'purchasing'].includes((deptName || '').toLowerCase());
}

function isProduksiDept(deptName) {
    const name = (deptName || '').toLowerCase();
    return name === 'produksi' || name === 'production';
}

async function getNotifCount(userId) {
    const r = await pool.query(
        `SELECT COUNT(*) FROM notifications WHERE recipient_user_id = $1 AND is_read = FALSE`,
        [userId]
    );
    return parseInt(r.rows[0].count);
}

async function getNotifications(userId, limit = 10) {
    const r = await pool.query(
        `SELECT * FROM notifications WHERE recipient_user_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [userId, limit]
    );
    return r.rows;
}

async function checkAndNotifyHighValueReport(reportId, user) {
    try {
        const totalRes = await pool.query('SELECT SUM(total_price) as total FROM daily_report_finance_detail WHERE report_id = $1', [reportId]);
        const total = parseFloat(totalRes.rows[0].total) || 0;
        if (total > 1000000) {
            const sdas = await pool.query("SELECT id FROM users WHERE role_id = (SELECT id FROM roles WHERE role_name = 'super_duper_admin') AND is_active = TRUE");
            for (const sda of sdas.rows) {
                await pool.query(`
                    INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id)
                    VALUES ($1, 'system', $2, 'high_value', $3)
                `, [sda.id, `Laporan pengeluaran tinggi Rp ${total.toLocaleString('id-ID')} dari ${user.full_name}`, reportId]);
            }
        }
    } catch (e) {
        console.error('High value notification error:', e);
    }
}

async function getReportFiles(reportId, tablePrefix = 'daily_report', clientPool = pool) {
    try {
        const attachTable = tablePrefix === 'director' ? 'director_report_attachments' : 'daily_report_attachments';
        const mainTable = tablePrefix === 'director' ? 'director_reports' : 'daily_report';

        const attachRes = await clientPool.query(`SELECT attachment_path FROM ${attachTable} WHERE report_id = $1`, [reportId]);
        const mainRes = await clientPool.query(`SELECT attachment_path FROM ${mainTable} WHERE id = $1`, [reportId]);

        const filesToDelete = new Set();
        attachRes.rows.forEach(r => { if (r.attachment_path) filesToDelete.add(r.attachment_path); });
        if (mainRes.rows[0] && mainRes.rows[0].attachment_path) {
            filesToDelete.add(mainRes.rows[0].attachment_path);
        }

        return Array.from(filesToDelete);
    } catch (err) {
        console.error('Error getting physical files for report ' + reportId + ':', err);
        return [];
    }
}

function executeDeleteFiles(files) {
    for (let file of files) {
        if (file) {
            const filePath = path.join(__dirname, 'public', file);
            if (fs.existsSync(filePath)) {
                try {
                    fs.unlinkSync(filePath);
                } catch (e) {
                    console.error('Failed to delete file:', file, e);
                }
            }
        }
    }
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect(req.session.user.isDirector ? '/director/dashboard' : '/dashboard');
    }
    res.redirect('/login');
});

// ── LOGIN ──────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect(req.session.user.isDirector ? '/director/dashboard' : '/dashboard');
    }
    if (req.session.tempUser) return res.redirect('/verify-mfa');
    res.render('login', { error: null });
});

app.get('/director/login', (req, res) => {
    if (req.session.user) {
        return res.redirect(req.session.user.isDirector ? '/director/dashboard' : '/dashboard');
    }
    if (req.session.tempUser) return res.redirect('/verify-mfa');
    res.render('login', { error: null, isDirector: true });
});

app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'Email dan password wajib diisi.' });
    }
    try {
        const result = await pool.query(`
            SELECT u.*, r.role_name, c.company_name, d.department_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            LEFT JOIN companies c ON u.company_id = c.id
            LEFT JOIN departments d ON u.department_id = d.id
            WHERE u.email = $1 AND u.is_active = TRUE
        `, [email.trim().toLowerCase()]);

        const user = result.rows[0];
        if (!user) return res.render('login', { error: 'Email atau password salah!' });

        let isMatch = false;
        if (user.password_hash.startsWith('$argon2')) {
            isMatch = await argon2.verify(user.password_hash, password);
        } else if (user.password_hash.startsWith('$2')) {
            isMatch = await bcrypt.compare(password, user.password_hash);
        } else {
            isMatch = (user.password_hash === password);
        }

        if (!isMatch) return res.render('login', { error: 'Email atau password salah!' });

        // Check MFA
        if (user.mfa_enabled) {
            req.session.tempUser = {
                id: user.id,
                full_name: user.full_name,
                email: user.email,
                role_name: user.role_name,
                company_id: user.company_id,
                company_name: user.company_name,
                department_id: user.department_id,
                department_name: user.department_name,
                position: user.position,
                isDirector: false
            };
            return res.redirect('/verify-mfa');
        }

        req.session.user = {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            role_name: user.role_name,
            company_id: user.company_id,
            company_name: user.company_name,
            department_id: user.department_id,
            department_name: user.department_name,
            position: user.position,
            isDirector: false
        };

        switch (user.role_name) {
            case 'super_duper_admin': return res.redirect('/sda/dashboard');
            case 'super_admin': return res.redirect('/sa/dashboard');
            case 'admin_divisi': return res.redirect('/admin/dashboard');
            default: return res.redirect('/dashboard');
        }
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Terjadi kesalahan sistem.' });
    }
});

app.post('/director/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'Email dan password wajib diisi.', isDirector: true });
    }
    try {
        const result = await pool.query(`
            SELECT u.*, r.role_name, c.company_name
            FROM director_users u
            JOIN director_roles r ON u.role_id = r.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE u.email = $1 AND u.is_active = TRUE
        `, [email.trim().toLowerCase()]);

        const user = result.rows[0];
        if (!user) return res.render('login', { error: 'Email atau password salah!', isDirector: true });

        let isMatch = false;
        if (user.password_hash.startsWith('$argon2')) {
            isMatch = await argon2.verify(user.password_hash, password);
        } else if (user.password_hash.startsWith('$2')) {
            isMatch = await bcrypt.compare(password, user.password_hash);
        } else {
            isMatch = (user.password_hash === password);
        }

        if (!isMatch) return res.render('login', { error: 'Email atau password salah!', isDirector: true });

        // Check MFA for director
        if (user.mfa_enabled) {
            req.session.tempUser = {
                id: user.id,
                full_name: user.full_name,
                email: user.email,
                role_name: user.role_name,
                position: user.position,
                company_id: user.company_id,
                company_name: user.company_name,
                isDirector: true
            };
            return res.redirect('/verify-mfa');
        }

        req.session.user = {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            role_name: user.role_name,
            position: user.position,
            company_id: user.company_id,
            company_name: user.company_name,
            isDirector: true
        };

        res.redirect('/director/dashboard');
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Terjadi kesalahan sistem.', isDirector: true });
    }
});

// ── MFA VERIFICATION ────────────────────────────────────────────────────────
app.get('/verify-mfa', (req, res) => {
    if (!req.session.tempUser) return res.redirect('/login');
    res.render('verify_mfa', { error: null });
});

app.post('/verify-mfa', mfaLimiter, async (req, res) => {
    let { token } = req.body;
    token = token ? token.replace(/\s+/g, '') : '';
    const tempUser = req.session.tempUser;

    if (!tempUser) return res.redirect('/login');

    try {
        // Validation input
        if (!token || token.trim().length === 0) {
            return res.render('verify_mfa', { error: 'Kode verifikasi tidak boleh kosong.' });
        }

        // Get MFA secret - use separate queries untuk menghindari SQL injection
        let result;
        if (tempUser.isDirector) {
            result = await pool.query(`SELECT mfa_secret FROM director_users WHERE id = $1`, [tempUser.id]);
        } else {
            result = await pool.query(`SELECT mfa_secret FROM users WHERE id = $1`, [tempUser.id]);
        }

        if (!result.rows[0] || !result.rows[0].mfa_secret) {
            return res.render('verify_mfa', { error: 'Data user tidak valid.' });
        }

        const secret = result.rows[0].mfa_secret;

        // Verify OTP using real NTP time to handle server clock mismatch
        const realTime = await getRealTime();
        let isValid = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            time: realTime,
            window: 2
        });

        if (isValid) {
            // Get fresh user data dari database
            let userData;
            if (tempUser.isDirector) {
                userData = await pool.query(
                    `SELECT u.id, u.full_name, u.email, r.role_name, p.position_name as position, u.company_id, c.company_name
                     FROM director_users u
                     LEFT JOIN director_roles r ON u.role_id = r.id
                     LEFT JOIN director_positions p ON u.position_id = p.id
                     LEFT JOIN companies c ON u.company_id = c.id
                     WHERE u.id = $1`,
                    [tempUser.id]
                );
            } else {
                userData = await pool.query(
                    `SELECT u.*, r.role_name, c.company_name, d.department_name
                     FROM users u
                     JOIN roles r ON u.role_id = r.id
                     LEFT JOIN companies c ON u.company_id = c.id
                     LEFT JOIN departments d ON u.department_id = d.id
                     WHERE u.id = $1`,
                    [tempUser.id]
                );
            }

            if (!userData.rows[0]) {
                return res.render('verify_mfa', { error: 'User tidak ditemukan.' });
            }

            // Set session dengan data fresh dari DB
            if (tempUser.isDirector) {
                req.session.user = {
                    ...userData.rows[0],
                    isDirector: true
                };
            } else {
                req.session.user = {
                    ...userData.rows[0],
                    isDirector: false
                };
            }

            delete req.session.tempUser;

            if (tempUser.isDirector) {
                return res.redirect('/director/dashboard');
            } else {
                switch (tempUser.role_name) {
                    case 'super_duper_admin': return res.redirect('/sda/dashboard');
                    case 'super_admin': return res.redirect('/sa/dashboard');
                    case 'admin_divisi': return res.redirect('/admin/dashboard');
                    default: return res.redirect('/dashboard');
                }
            }
        } else {
            res.render('verify_mfa', { error: 'Kode verifikasi salah atau kedaluwarsa.' });
        }
    } catch (err) {
        console.error('MFA Verification Error:', err);
        res.render('verify_mfa', { error: 'Terjadi kesalahan sistem.' });
    }
});

// ── LOGOUT ─────────────────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
    const wasDirector = req.session?.user?.isDirector;
    req.session = null;
    res.redirect(wasDirector ? '/director/login' : '/login');
});

// ── HELPER: render dengan notif ────────────────────────────────────────────────
async function renderWithNotif(res, view, data, userId) {
    try {
        const notifCount = userId ? await getNotifCount(userId) : 0;
        const notifications = userId ? await getNotifications(userId) : [];
        // Urgent count for SDA sidebar badge
        let urgentCount = 0;
        if (userId) {
            try {
                const uRes = await pool.query(`
                    SELECT COUNT(*) FROM daily_report 
                    WHERE is_asked_director = TRUE 
                      AND (solution IS NULL OR solution = '') 
                      AND (manager_note IS NULL OR manager_note = '')
                `);
                urgentCount = parseInt(uRes.rows[0].count) || 0;
            } catch (e) { /* ignore */ }
        }
        res.render(view, { ...data, notifCount, notifications, urgentCount, query: res.req.query });
    } catch (e) {
        res.render(view, { ...data, notifCount: 0, notifications: [], urgentCount: 0, query: res.req.query });
    }
}

// ── DIRECTOR MODE HELPERS ──────────────────────────────────────────────────────
async function getNotifCountDirector(userId) {
    const r = await pool.query(
        `SELECT COUNT(*) FROM director_notifications WHERE recipient_user_id = $1 AND is_read = FALSE`,
        [userId]
    );
    return parseInt(r.rows[0].count);
}

async function getNotificationsDirector(userId) {
    const r = await pool.query(
        `SELECT * FROM director_notifications WHERE recipient_user_id = $1 ORDER BY created_at DESC LIMIT 10`,
        [userId]
    );
    return r.rows;
}

async function renderWithNotifDirector(res, view, data, userId) {
    try {
        const notifCount = userId ? await getNotifCountDirector(userId) : 0;
        const notifications = userId ? await getNotificationsDirector(userId) : [];
        res.render(view, { ...data, notifCount, notifications, query: res.req.query });
    } catch (e) {
        res.render(view, { ...data, notifCount: 0, notifications: [], query: res.req.query });
    }
}

async function auditLogDirector(userId, action, table, targetId, oldVal, newVal, ip) {
    try {
        await pool.query(`
            INSERT INTO director_audit_logs (user_id, action, target_table, target_id, old_value, new_value, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [userId, action, table, targetId, JSON.stringify(oldVal), JSON.stringify(newVal), ip]);
    } catch (e) {
        console.error('Director Audit Log Error:', e);
    }
}

app.get('/director/employees', isDirectorAuth, async (req, res) => {
    const user = req.session.user;
    const { position_id, search } = req.query;

    try {
        // Query to get all director positions and user counts from 'director_users' table
        let posSql = `
            SELECT p.id, p.position_name, 
                   (SELECT COUNT(*) FROM director_users u WHERE u.position_id = p.id ${user.company_id ? 'AND u.company_id = $1' : ''}) as employee_count
            FROM director_positions p
            ORDER BY p.position_name ASC
        `;
        const posParams = user.company_id ? [user.company_id] : [];
        const posStats = await pool.query(posSql, posParams);

        let employees = [];
        let selectedPos = null;

        if (position_id) {
            const posRes = await pool.query('SELECT * FROM director_positions WHERE id = $1', [position_id]);
            selectedPos = posRes.rows[0];

            let empSql = `
                SELECT u.*, r.role_name, p.position_name, c.company_name
                FROM director_users u
                JOIN director_roles r ON u.role_id = r.id
                JOIN director_positions p ON u.position_id = p.id
                LEFT JOIN companies c ON u.company_id = c.id
                WHERE u.position_id = $1
            `;
            const empParams = [position_id];

            if (user.company_id) {
                empSql += ` AND u.company_id = $2`;
                empParams.push(user.company_id);
            }

            if (search) {
                const searchIdx = empParams.length + 1;
                empSql += ` AND (u.full_name ILIKE $${searchIdx} OR u.email ILIKE $${searchIdx})`;
                empParams.push(`%${search}%`);
            }

            empSql += ` ORDER BY u.full_name ASC`;
            const empRes = await pool.query(empSql, empParams);
            employees = empRes.rows;
        }

        await renderWithNotifDirector(res, 'director/employees', {
            user,
            posStats: posStats.rows,
            employees,
            selectedPos,
            filters: { position_id, search },
            activePage: 'director_employees'
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

// ── DIRECTOR MODE ROUTES ───────────────────────────────────────────────────────
app.get(['/director/activity_log', '/director/activity-log'], isDirectorAuth, authorizeDirector('super_admin', 'super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const { date } = req.query;
    try {
        const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
        const targetDate = date || todayStr;

        const notReported = await pool.query(`
            SELECT u.full_name, p.position_name as position, c.company_name
            FROM director_users u
            LEFT JOIN director_positions p ON u.position_id = p.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE u.is_active = TRUE
              AND u.id NOT IN (
                SELECT user_id FROM director_reports 
                WHERE report_date = $1
              )
            ORDER BY u.full_name
        `, [targetDate]);

        const reported = await pool.query(`
            SELECT u.full_name, p.position_name as position, c.company_name, dr.report_time, dr.id as report_id
            FROM director_users u
            JOIN director_reports dr ON u.id = dr.user_id
            LEFT JOIN director_positions p ON u.position_id = p.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE dr.report_date = $1
            ORDER BY dr.report_time DESC
        `, [targetDate]);

        await renderWithNotifDirector(res, 'director/activity_log', {
            user,
            notReported: notReported.rows,
            reported: reported.rows,
            todayStr: targetDate,
            selectedDate: targetDate,
            activePage: 'activity_log'
        }, user.id);
    } catch (err) {
        console.error('[ERROR] /director/activity_log:', err);
        res.status(500).send(err.message);
    }
});

app.get('/director/dashboard', isDirectorAuth, async (req, res) => {
    const user = req.session.user;
    try {
        const reports = await pool.query(`
            SELECT dr.*, u.full_name, p.position_name
            FROM director_reports dr 
            JOIN director_users u ON dr.user_id = u.id
            LEFT JOIN director_positions p ON u.position_id = p.id
            ORDER BY 
                dr.report_date DESC, 
                CASE WHEN dr.status = 'approved' THEN 1 ELSE 0 END ASC,
                dr.report_time DESC
        `);

        const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());

        const notReportedRes = await pool.query(`
            SELECT u.id, u.full_name
            FROM director_users u
            WHERE u.is_active = TRUE
              AND u.id NOT IN (
                SELECT user_id FROM director_reports 
                WHERE report_date = $1
              )
        `, [todayStr]);

        renderWithNotifDirector(res, 'director/dashboard', {
            user,
            reports: reports.rows,
            notReported: notReportedRes.rows,
            todayStr
        }, user.id);
    } catch (err) {
        console.error(err);
        res.render('500', { error: err.message, user });
    }
});

app.get('/director/report/new', isDirectorAuth, async (req, res) => {
    const user = req.session.user;
    const now = new Date();
    renderWithNotifDirector(res, 'director/form_report', { user, report: null, attachments: [], error: null, now }, user.id);
});

app.post('/director/report/new', isDirectorAuth, upload.array('attachments', 10), async (req, res) => {
    const user = req.session.user;
    const { report_date, report_time, task_description, issue, solution, result, status_action } = req.body;
    const status = status_action === 'submit' ? 'submitted' : 'draft';
    const attachments = req.files || [];

    const now = new Date();
    const jakartaDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(now);
    const jakartaTime = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Jakarta', hour: '2-digit', minute: '2-digit', hour12: false }).format(now);

    const date = report_date || jakartaDate;
    const time = report_time || jakartaTime;

    try {
        const firstAttachment = attachments.length > 0 ? '/uploads/' + attachments[0].filename : null;
        const rpt = await pool.query(`
            INSERT INTO director_reports 
            (user_id, report_date, report_time, task_description, issue, solution, result, status, attachment_path)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id
        `, [user.id, date, time, task_description, issue, solution, result, status, firstAttachment]);

        const reportId = rpt.rows[0].id;

        if (attachments && attachments.length > 0) {
            for (const file of attachments) {
                const filePath = '/uploads/' + file.filename;
                await pool.query('INSERT INTO director_report_attachments (report_id, attachment_path) VALUES ($1, $2)', [reportId, filePath]);
            }
        }

        await auditLogDirector(user.id, 'create_report', 'director_reports', reportId, null, { status, date }, req.ip);

        res.redirect('/director/dashboard?msg=added');
    } catch (err) {
        console.error(err);
        renderWithNotifDirector(res, 'director/form_report', { user, error: err.message }, user.id);
    }
});

app.post('/director/report/approve/:id', isDirectorAuth, async (req, res) => {
    try {
        await pool.query('UPDATE director_reports SET status = $1 WHERE id = $2', ['approved', req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

app.get('/director/report/:id', isDirectorAuth, async (req, res) => {
    const user = req.session.user;
    try {
        const rpt = await pool.query(`
            SELECT dr.*, u.full_name, u.position
            FROM director_reports dr
            JOIN director_users u ON dr.user_id = u.id
            WHERE dr.id = $1
        `, [req.params.id]);
        if (!rpt.rows[0]) return res.redirect('/director/dashboard');

        const attRes = await pool.query(
            'SELECT * FROM director_report_attachments WHERE report_id = $1 ORDER BY id ASC',
            [req.params.id]
        );

        renderWithNotifDirector(res, 'director/report_detail', {
            user,
            report: rpt.rows[0],
            attachments: attRes.rows
        }, user.id);
    } catch (err) { res.redirect('/director/dashboard'); }
});

app.get('/director/report/edit/:id', isDirectorAuth, async (req, res) => {
    try {
        const rpt = await pool.query('SELECT * FROM director_reports WHERE id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
        if (!rpt.rows[0]) return res.redirect('/director/dashboard');
        renderWithNotifDirector(res, 'director/form_report', { user: req.session.user, report: rpt.rows[0], error: null }, req.session.user.id);
    } catch (err) { res.redirect('/director/dashboard'); }
});

app.post('/director/report/edit/:id', isDirectorAuth, upload.array('attachments', 10), async (req, res) => {
    const { task_description, issue, solution, result, status_action } = req.body;
    const status = status_action === 'submit' ? 'submitted' : 'draft';
    try {
        await pool.query(`
            UPDATE director_reports 
            SET task_description=$1, issue=$2, solution=$3, result=$4, status=$5
            WHERE id=$6 AND user_id=$7
        `, [task_description, issue, solution, result, status, req.params.id, req.session.user.id]);
        res.redirect('/director/dashboard?msg=updated');
    } catch (err) { res.redirect('/director/dashboard'); }
});

app.post('/director/report/delete/:id', isDirectorAuth, async (req, res) => {
    try {
        const reportId = req.params.id;
        const userId = req.session.user.id;
        const role = req.session.user.role_name;

        await auditLogDirector(userId, 'DELETE', 'director_reports', reportId, { status: 'EXISTS' }, { status: 'DELETED' }, req.ip);

        const filesToDel = await getReportFiles(reportId, 'director', pool);

        // Hapus notifikasi terkait laporan ini
        await pool.query('DELETE FROM director_notifications WHERE reference_id = $1', [reportId]);

        if (role === 'super_duper_admin') {
            await pool.query('DELETE FROM director_reports WHERE id = $1', [reportId]);
            executeDeleteFiles(filesToDel);
        } else {
            const delRes = await pool.query('DELETE FROM director_reports WHERE id = $1 AND user_id = $2 RETURNING id', [reportId, userId]);
            if (delRes.rowCount > 0) {
                executeDeleteFiles(filesToDel);
            }
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: err.message });
    }
});

app.get('/director/notif/read/:id', isDirectorAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE director_notifications SET is_read=TRUE WHERE id=$1 AND recipient_user_id=$2`, [req.params.id, req.session.user.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/director/notif/read-all', isDirectorAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE director_notifications SET is_read=TRUE WHERE recipient_user_id=$1`, [req.session.user.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/director/attachment/:filename', isDirectorAuth, (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    if (filename.includes('..') || filename.includes('/')) {
        return res.status(400).send('Invalid filename');
    }
    const filePath = path.join(__dirname, 'public', 'uploads', filename);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.redirect('/director/dashboard?err=file_not_found');
    }
});

app.get('/director/attachment/view/:filename', isDirectorAuth, async (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    try {
        let reportId = null;
        let attachments = [];

        const detailRes = await pool.query('SELECT report_id FROM director_report_attachments WHERE attachment_path LIKE $1', [`%${filename}`]);
        if (detailRes.rows.length > 0) {
            reportId = detailRes.rows[0].report_id;
        } else {
            const mainRes = await pool.query('SELECT id FROM director_reports WHERE attachment_path LIKE $1', [`%${filename}`]);
            if (mainRes.rows.length > 0) reportId = mainRes.rows[0].id;
        }

        if (reportId) {
            const allAtt = await pool.query('SELECT * FROM director_report_attachments WHERE report_id = $1', [reportId]);
            attachments = allAtt.rows;

            if (attachments.length === 0) {
                const report = await pool.query('SELECT attachment_path FROM director_reports WHERE id = $1', [reportId]);
                if (report.rows[0] && report.rows[0].attachment_path) {
                    attachments.push({
                        report_id: reportId,
                        attachment_path: report.rows[0].attachment_path
                    });
                }
            }
        }

        renderWithNotifDirector(res, 'director/attachment_view', { filename, attachments, reportId, user: req.session.user }, req.session.user.id);
    } catch (err) {
        console.error(err);
        renderWithNotifDirector(res, 'director/attachment_view', { filename, attachments: [], reportId: null, user: req.session.user }, req.session.user.id);
    }
});

// ── DIRECTOR USER MANAGEMENT ───────────────────────────────────────────────────
app.get('/director/users', authorizeDirector('super_duper_admin'), async (req, res) => {
    const { search } = req.query;
    try {
        let sql = `
            SELECT u.*, r.role_name, p.position_name, c.company_name
            FROM director_users u 
            JOIN director_roles r ON u.role_id = r.id 
            LEFT JOIN director_positions p ON u.position_id = p.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1
        `;
        const params = [];
        if (search) {
            sql += ` AND (u.full_name ILIKE $1 OR u.email ILIKE $1)`;
            params.push(`%${search}%`);
        }
        sql += ` ORDER BY u.full_name ASC`;

        const users = await pool.query(sql, params);
        const roles = await pool.query('SELECT * FROM director_roles ORDER BY role_name ASC');
        const positions = await pool.query('SELECT * FROM director_positions ORDER BY position_name ASC');
        const companies = await pool.query('SELECT id, company_name FROM companies WHERE is_active = TRUE ORDER BY company_name ASC');
        renderWithNotifDirector(res, 'director/users', {
            user: req.session.user,
            users: users.rows,
            roles: roles.rows,
            positions: positions.rows,
            companies: companies.rows,
            filters: { search },
            msg: req.query.msg,
            err: req.query.err
        }, req.session.user.id);
    } catch (err) {
        console.error(err);
        res.redirect('/director/dashboard');
    }
});

app.post('/director/users/add', authorizeDirector('super_duper_admin'), async (req, res) => {
    const { full_name, email, password, role_id, position_id, is_active, company_id } = req.body;
    try {
        const hashed = await argon2.hash(password);
        await pool.query(`
            INSERT INTO director_users (full_name, email, password_hash, role_id, position_id, is_active, company_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [full_name, email.toLowerCase(), hashed, role_id, position_id || null, is_active === 'true', company_id || null]);
        res.redirect('/director/users?msg=added');
    } catch (err) { res.redirect('/director/users?err=' + encodeURIComponent(err.message)); }
});

app.post('/director/users/edit/:id', authorizeDirector('super_duper_admin'), async (req, res) => {
    const { full_name, email, password, role_id, position_id, is_active, company_id } = req.body;
    try {
        if (password) {
            const hashed = await argon2.hash(password);
            await pool.query(`
                UPDATE director_users 
                SET full_name=$1, email=$2, password_hash=$3, role_id=$4, position_id=$5, is_active=$6, company_id=$7
                WHERE id=$8
            `, [full_name, email.toLowerCase(), hashed, role_id, position_id || null, is_active === 'true', company_id || null, req.params.id]);
        } else {
            await pool.query(`
                UPDATE director_users 
                SET full_name=$1, email=$2, role_id=$3, position_id=$4, is_active=$5, company_id=$6
                WHERE id=$7
            `, [full_name, email.toLowerCase(), role_id, position_id || null, is_active === 'true', company_id || null, req.params.id]);
        }
        res.redirect('/director/users?msg=updated');
    } catch (err) { res.redirect('/director/users?err=' + encodeURIComponent(err.message)); }
});

app.post('/director/users/delete/:id', authorizeDirector('super_duper_admin'), async (req, res) => {
    try {
        await pool.query('DELETE FROM director_users WHERE id = $1', [req.params.id]);
        res.redirect('/director/users?msg=deleted');
    } catch (err) { res.redirect('/director/users?err=' + encodeURIComponent(err.message)); }
});

// ── DIRECTOR POSITION MANAGEMENT ───────────────────────────────────────────────
app.get('/director/positions', authorizeDirector('super_duper_admin'), async (req, res) => {
    try {
        const positions = await pool.query('SELECT * FROM director_positions ORDER BY position_name ASC');
        renderWithNotifDirector(res, 'director/positions', {
            user: req.session.user,
            positions: positions.rows,
            msg: req.query.msg,
            err: req.query.err
        }, req.session.user.id);
    } catch (err) { res.redirect('/director/dashboard'); }
});

app.post('/director/positions/add', authorizeDirector('super_duper_admin'), async (req, res) => {
    try {
        await pool.query('INSERT INTO director_positions (position_name) VALUES ($1)', [req.body.position_name]);
        res.redirect('/director/positions?msg=added');
    } catch (err) { res.redirect('/director/positions?err=' + encodeURIComponent(err.message)); }
});

app.post('/director/positions/edit/:id', authorizeDirector('super_duper_admin'), async (req, res) => {
    try {
        await pool.query('UPDATE director_positions SET position_name=$1 WHERE id=$2', [req.body.position_name, req.params.id]);
        res.redirect('/director/positions?msg=updated');
    } catch (err) { res.redirect('/director/positions?err=' + encodeURIComponent(err.message)); }
});

app.post('/director/positions/delete/:id', authorizeDirector('super_duper_admin'), async (req, res) => {
    try {
        await pool.query('DELETE FROM director_positions WHERE id = $1', [req.params.id]);
        res.redirect('/director/positions?msg=deleted');
    } catch (err) { res.redirect('/director/positions?err=' + encodeURIComponent(err.message)); }
});

// Director Export
app.get('/director/export/excel', isDirectorAuth, async (req, res) => {
    try {
        const reports = await pool.query(`
            SELECT dr.*, u.full_name FROM director_reports dr 
            JOIN director_users u ON dr.user_id = u.id ORDER BY dr.report_date DESC
        `);
        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet('Executive Reports');
        sheet.columns = [
            { header: 'Tanggal', key: 'date', width: 15 },
            { header: 'Tugas', key: 'task', width: 40 },
            { header: 'Status', key: 'status', width: 15 }
        ];
        reports.rows.forEach(r => {
            sheet.addRow({ date: r.report_date, task: r.task_description, status: r.status.toUpperCase() });
        });
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Executive_Reports.xlsx');
        await workbook.xlsx.write(res); res.end();
    } catch (err) { res.status(500).send(err.message); }
});

app.get('/director/export/pdf', isDirectorAuth, async (req, res) => {
    try {
        const reports = await pool.query('SELECT * FROM director_reports ORDER BY report_date DESC');
        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=Executive_Reports.pdf');
        doc.pipe(res);
        doc.fontSize(20).text('Executive Reports', { align: 'center' });
        reports.rows.forEach(r => {
            doc.moveDown().fontSize(12).text(`[${r.report_date.toLocaleDateString()}] ${r.task_description}`);
        });
        doc.end();
    } catch (err) { res.status(500).send(err.message); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ROLE: USER — Dashboard dan laporan pribadi
// ══════════════════════════════════════════════════════════════════════════════

app.get('/dashboard', isAuth, authorize('user'), async (req, res) => {
    const user = req.session.user;
    try {
        const reports = await pool.query(`
            SELECT dr.*, d.department_name
            FROM daily_report dr
            LEFT JOIN departments d ON dr.department_id = d.id
            WHERE dr.user_id = $1
            ORDER BY dr.report_date DESC, dr.created_at DESC
            LIMIT 30
        `, [user.id]);

        await renderWithNotif(res, 'user/dashboard', { user, reports: reports.rows }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error: ' + err.message);
    }
});

app.get('/report/new', isAuth, authorize('user'), (req, res) => {
    const user = req.session.user;
    renderWithNotif(res, 'user/form_report', { user, error: null }, user.id);
});

app.post('/report/new', isAuth, authorize('user'), upload.array('attachments', 10), async (req, res) => {
    const user = req.session.user;
    const { report_date, report_time, task_description, issue, solution, result, status_action } = req.body;
    const attachments = req.files || [];
    const status = status_action === 'submit' ? 'submitted' : 'draft';

    const now = new Date();
    const jakartaDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(now);
    const jakartaTime = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Jakarta', hour: '2-digit', minute: '2-digit', hour12: false }).format(now);

    const date = report_date || jakartaDate;
    const time = report_time || jakartaTime;

    try {
        const firstAttachment = attachments.length > 0 ? '/uploads/' + attachments[0].filename : null;
        const rpt = await pool.query(`
            INSERT INTO daily_report 
            (user_id, report_date, report_time, task_description, issue, solution, result, status, attachment_path, department_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id
        `, [user.id, date, time, task_description, issue, solution, result, status, firstAttachment, user.department_id]);

        const reportId = rpt.rows[0].id;

        for (const file of attachments) {
            await pool.query(`
                INSERT INTO daily_report_attachments (report_id, attachment_path, file_type)
                VALUES ($1, $2, $3)
            `, [reportId, '/uploads/' + file.filename, file.mimetype]);
        }

        // Finance detail items
        const deptName = user.department_name || '';
        if (isFinanceDept(deptName)) {
            const items = Array.isArray(req.body.item_name) ? req.body.item_name : (req.body.item_name ? [req.body.item_name] : []);
            const qtys = Array.isArray(req.body.qty) ? req.body.qty : (req.body.qty ? [req.body.qty] : []);
            const prices = Array.isArray(req.body.unit_price) ? req.body.unit_price : (req.body.unit_price ? [req.body.unit_price] : []);

            for (let i = 0; i < items.length; i++) {
                if (items[i]) {
                    const qty = parseFloat(qtys[i]) || 0;
                    const unitPrice = parseFloat(prices[i]) || 0;
                    await pool.query(`
                        INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price)
                        VALUES ($1,$2,$3,$4,$5)
                    `, [reportId, items[i], qty, unitPrice, qty * unitPrice]);
                }
            }
        }

        // Produksi detail
        if (isProduksiDept(user.department_name)) {
            const qtyProd = parseFloat(req.body.qty) || 0;
            if (qtyProd > 0) {
                await pool.query(`
                    INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price)
                    VALUES ($1, 'Hasil Produksi', $2, 0, 0)
                `, [reportId, qtyProd]);
            }
        }

        await req.writeAudit('create_report', 'daily_report', reportId, null, { status, date });

        if (status === 'submitted') {
            await checkAndNotifyHighValueReport(reportId, user);
        }

        res.redirect('/dashboard?msg=added');
    } catch (err) {
        console.error(err);
        renderWithNotif(res, 'user/form_report', { user, error: err.message }, user.id);
    }
});

app.get('/report/edit/:id', isAuth, authorize('user'), async (req, res) => {
    const user = req.session.user;
    try {
        const rpt = await pool.query(`
            SELECT dr.*, array_agg(row_to_json(fd)) FILTER (WHERE fd.id IS NOT NULL) as finance_items
            FROM daily_report dr
            LEFT JOIN daily_report_finance_detail fd ON fd.report_id = dr.id
            WHERE dr.id = $1 AND dr.user_id = $2
            GROUP BY dr.id
        `, [req.params.id, user.id]);

        if (!rpt.rows[0]) return res.redirect('/dashboard');
        const report = rpt.rows[0];
        if (report.status === 'approved') return res.redirect('/dashboard?err=approved_locked');

        const attRes = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
        const attachments = attRes.rows;

        await renderWithNotif(res, 'user/form_report', { user, report, attachments, error: null }, user.id);
    } catch (err) {
        res.redirect('/dashboard');
    }
});

app.post('/report/edit/:id', isAuth, authorize('user'), upload.array('attachments', 10), async (req, res) => {
    const user = req.session.user;
    const { task_description, issue, solution, result, status_action } = req.body;
    const status = status_action === 'submit' ? 'submitted' : 'draft';
    const reportId = req.params.id;

    try {
        const existing = await pool.query(`SELECT * FROM daily_report WHERE id=$1 AND user_id=$2`, [reportId, user.id]);
        if (!existing.rows[0] || existing.rows[0].status === 'approved') {
            return res.redirect('/dashboard?err=not_allowed');
        }

        const oldVal = existing.rows[0];
        const attachments = req.files || [];
        const firstAttachment = attachments.length > 0 ? '/uploads/' + attachments[0].filename : oldVal.attachment_path;

        await pool.query(`
            UPDATE daily_report SET task_description=$1, issue=$2, solution=$3, result=$4, status=$5, attachment_path=$6
            WHERE id=$7 AND user_id=$8
        `, [task_description, issue, solution, result, status, firstAttachment, reportId, user.id]);

        if (attachments.length > 0) {
            const oldFilesToDel = await getReportFiles(reportId, 'daily_report', pool);
            await pool.query('DELETE FROM daily_report_attachments WHERE report_id=$1', [reportId]);
            executeDeleteFiles(oldFilesToDel);
            for (const file of attachments) {
                await pool.query(`
                    INSERT INTO daily_report_attachments (report_id, attachment_path, file_type)
                    VALUES ($1, $2, $3)
                `, [reportId, '/uploads/' + file.filename, file.mimetype]);
            }
        }

        if (isFinanceDept(user.department_name)) {
            await pool.query('DELETE FROM daily_report_finance_detail WHERE report_id=$1', [reportId]);
            const items = Array.isArray(req.body.item_name) ? req.body.item_name : (req.body.item_name ? [req.body.item_name] : []);
            const qtys = Array.isArray(req.body.qty) ? req.body.qty : (req.body.qty ? [req.body.qty] : []);
            const prices = Array.isArray(req.body.unit_price) ? req.body.unit_price : (req.body.unit_price ? [req.body.unit_price] : []);
            for (let i = 0; i < items.length; i++) {
                if (items[i]) {
                    const qty = parseFloat(qtys[i]) || 0;
                    const up = parseFloat(prices[i]) || 0;
                    await pool.query(`
                        INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price)
                        VALUES ($1,$2,$3,$4,$5)
                    `, [reportId, items[i], qty, up, qty * up]);
                }
            }
        }

        if (isProduksiDept(user.department_name)) {
            await pool.query('DELETE FROM daily_report_finance_detail WHERE report_id=$1', [reportId]);
            const qtyProd = parseFloat(req.body.qty) || 0;
            if (qtyProd > 0) {
                await pool.query(`
                    INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price)
                    VALUES ($1, 'Hasil Produksi', $2, 0, 0)
                `, [reportId, qtyProd]);
            }
        }

        await req.writeAudit('edit_report', 'daily_report', reportId, oldVal, { status });

        if (status === 'submitted') {
            await checkAndNotifyHighValueReport(reportId, user);
        }

        res.redirect('/dashboard?msg=updated');
    } catch (err) {
        console.error(err);
        res.redirect('/dashboard?err=' + encodeURIComponent(err.message));
    }
});

app.get('/report/:id', isAuth, authorize('user'), async (req, res) => {
    const user = req.session.user;
    try {
        const rpt = await pool.query(`
            SELECT dr.*, d.department_name
            FROM daily_report dr
            JOIN departments d ON dr.department_id = d.id
            WHERE dr.id = $1 AND dr.user_id = $2
        `, [req.params.id, user.id]);

        if (!rpt.rows[0]) return res.redirect('/dashboard');
        const report = rpt.rows[0];

        let financeItems = [];
        if (isFinanceDept(report.department_name) || isProduksiDept(report.department_name)) {
            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            financeItems = fd.rows;
        }

        const attRes = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
        const attachments = attRes.rows;

        await renderWithNotif(res, 'user/report_detail', { user, report, financeItems, attachments }, user.id);
    } catch (err) {
        console.error(err);
        res.redirect('/dashboard');
    }
});

app.post('/report/approve/:id', isAuth, authorize('user'), async (req, res) => {
    const user = req.session.user;
    const reportId = req.params.id;

    try {
        const check = await pool.query(`SELECT * FROM daily_report WHERE id=$1 AND user_id=$2`, [reportId, user.id]);
        if (!check.rows[0]) return res.status(403).json({ success: false, message: 'Akses ditolak' });

        const report = check.rows[0];
        if (report.status === 'approved') return res.json({ success: true, message: 'Sudah di-approve' });

        await pool.query(`UPDATE daily_report SET status='approved' WHERE id=$1`, [reportId]);
        await req.writeAudit('self_approve', 'daily_report', reportId, { status: report.status }, { status: 'approved' });

        res.json({ success: true, message: 'Laporan berhasil Anda approve sendiri' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ══════════════════════════════════════════════════════════════════════════════
// ROLE: ADMIN DIVISI
// ══════════════════════════════════════════════════════════════════════════════

app.get('/admin/dashboard', isAuth, authorize('admin_divisi'), async (req, res) => {
    const user = req.session.user;
    const { date_from, date_to, status, search } = req.query;

    try {
        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            WHERE u.department_id = $1 AND u.company_id = $2
        `;
        const params = [user.department_id, user.company_id];

        if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
        if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
        if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
        if (search) { sql += ` AND (u.full_name ILIKE $${params.length + 1})`; params.push(`%${search}%`); }

        sql += ` ORDER BY dr.report_date DESC, (CASE WHEN dr.status = 'approved' THEN 2 ELSE 1 END) ASC, dr.created_at DESC`;
        const reports = await pool.query(sql, params);

        const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());

        const notReportedRes = await pool.query(`
            SELECT u.id, u.full_name
            FROM users u
            WHERE u.department_id = $1 AND u.company_id = $2 AND u.is_active = TRUE
              AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
              AND u.id NOT IN (
                SELECT user_id FROM daily_report 
                WHERE report_date = $3
              )
        `, [user.department_id, user.company_id, todayStr]);

        const totalStaffRes = await pool.query(`
            SELECT COUNT(*) as total FROM users
            WHERE department_id = $1 AND company_id = $2 AND is_active = TRUE
              AND role_id = (SELECT id FROM roles WHERE role_name = 'user')
        `, [user.department_id, user.company_id]);
        const totalStaff = parseInt(totalStaffRes.rows[0].total);

        await renderWithNotif(res, 'admin/dashboard', {
            user,
            reports: reports.rows,
            notReported: notReportedRes.rows,
            totalStaff,
            todayStr,
            filters: { date_from, date_to, status, search }
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

app.post('/admin/report/delete/:id', isAuth, authorize('admin_divisi', 'super_admin', 'super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const reportId = req.params.id;

    try {
        const check = await pool.query(`
            SELECT dr.*, u.company_id AS u_company_id, u.department_id AS u_department_id
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            WHERE dr.id = $1
        `, [reportId]);

        if (!check.rows[0]) return res.status(404).json({ success: false, message: 'Laporan tidak ditemukan' });
        const report = check.rows[0];

        if (user.role_name === 'admin_divisi' && parseInt(report.u_department_id) !== parseInt(user.department_id)) {
            return res.status(403).json({ success: false, message: 'Akses ditolak (Divisi berbeda)' });
        }
        if (user.role_name === 'super_admin' && parseInt(report.u_company_id) !== parseInt(user.company_id)) {
            return res.status(403).json({ success: false, message: 'Akses ditolak (PT berbeda)' });
        }

        const filesToDel = await getReportFiles(reportId, 'daily_report', pool);

        // Hapus notifikasi terkait laporan ini
        await pool.query('DELETE FROM notifications WHERE reference_id = $1', [reportId]);

        await pool.query('DELETE FROM daily_report WHERE id = $1', [reportId]);
        executeDeleteFiles(filesToDel);
        await req.writeAudit('delete_report', 'daily_report', reportId, report, null);

        res.json({ success: true, message: 'Laporan berhasil dihapus' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/admin/review/:id', isAuth, authorize('admin_divisi', 'super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const { manager_note, new_status } = req.body;
    const reportId = req.params.id;

    try {
        const check = await pool.query(`
            SELECT dr.*, u.full_name FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            WHERE dr.id = $1
        `, [reportId]);

        if (!check.rows[0]) return res.status(404).json({ success: false, message: 'Laporan tidak ditemukan' });

        const report = check.rows[0];

        if (user.role_name !== 'super_duper_admin') {
            if (report.department_id !== user.department_id) {
                return res.status(403).json({ success: false, message: 'Akses ditolak' });
            }
        }

        const old = report;
        await pool.query(`
            UPDATE daily_report SET manager_note=$1, status=$2 WHERE id=$3
        `, [manager_note, new_status || old.status, reportId]);

        await req.writeAudit('review_report', 'daily_report', reportId, { status: old.status }, { status: new_status, manager_note });

        const notifType = new_status === 'approved' ? 'laporan_diapprove' : 'laporan_direview';
        let notifMsg = `Laporan Anda tanggal ${new Date(old.report_date).toLocaleDateString()} telah direview oleh ${user.full_name}.`;
        if (new_status === 'approved') notifMsg = `Laporan Anda telah disetujui (Approved) oleh ${user.full_name}.`;
        else if (new_status === 'rejected') notifMsg = `Laporan Anda ditolak/perlu revisi. Catatan: ${manager_note}`;

        await pool.query(`
            INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id)
            VALUES ($1, 'system', $2, $3, $4)
        `, [old.user_id, notifMsg, notifType, reportId]);

        res.json({ success: true, message: 'Review berhasil disimpan' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/admin/report/:id', isAuth, authorize('admin_divisi', 'super_admin', 'super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    if (user.role_name === 'super_duper_admin') {
        return res.redirect('/sda/report/' + req.params.id);
    }
    try {

        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE dr.id = $1
        `;
        const params = [req.params.id];

        if (user.role_name === 'admin_divisi') {
            sql += ` AND u.department_id = $2`;
            params.push(user.department_id);
        } else if (user.role_name === 'super_admin') {
            sql += ` AND u.company_id = $2`;
            params.push(user.company_id);
        }

        const rpt = await pool.query(sql, params);
        if (!rpt.rows[0]) return res.redirect('/admin/dashboard');
        const report = rpt.rows[0];

        let financeItems = [];
        if (isFinanceDept(report.department_name) || isProduksiDept(report.department_name)) {
            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            financeItems = fd.rows;
        }

        const attRes = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
        const attachments = attRes.rows;

        const viewMap = {
            admin_divisi: 'admin/report_detail',
            super_admin: 'superadmin/report_detail',
            super_duper_admin: 'sda/report_detail',
        };

        await renderWithNotif(res, viewMap[user.role_name] || 'admin/report_detail', {
            user, report, financeItems, attachments
        }, user.id);
    } catch (err) {
        console.error(err);
        const redirectMap = {
            super_duper_admin: '/sda/dashboard',
            super_admin: '/sa/dashboard',
            admin_divisi: '/admin/dashboard'
        };
        res.redirect((redirectMap[user.role_name] || '/dashboard') + '?err=' + encodeURIComponent(err.message));
    }
});

app.get('/admin/users', isAuth, authorize('admin_divisi'), async (req, res) => {
    const user = req.session.user;
    const { search } = req.query;
    try {
        let sql = `
            SELECT u.*, r.role_name
            FROM users u JOIN roles r ON u.role_id = r.id
            WHERE u.department_id = $1 AND u.company_id = $2
        `;
        const params = [user.department_id, user.company_id];

        if (search) {
            sql += ` AND (u.full_name ILIKE $3 OR u.email ILIKE $3 OR u.position ILIKE $3)`;
            params.push(`%${search}%`);
        }

        sql += ` ORDER BY u.full_name`;
        const users = await pool.query(sql, params);

        await renderWithNotif(res, 'admin/users', {
            user,
            users: users.rows,
            filters: { search }
        }, user.id);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/admin/users/add', isAuth, authorize('admin_divisi'), async (req, res) => {
    const user = req.session.user;
    const { full_name, email, password, position } = req.body;
    try {
        const hash = await argon2.hash(password);
        const roleIdRes = await pool.query("SELECT id FROM roles WHERE role_name='user'");
        const roleId = roleIdRes.rows[0].id;

        const rpt = await pool.query(`
            INSERT INTO users (full_name, email, password_hash, role_id, position, company_id, department_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
        `, [full_name, email.toLowerCase(), hash, roleId, position, user.company_id, user.department_id]);

        await req.writeAudit('create_user_admin', 'users', rpt.rows[0].id, null, { email, department_id: user.department_id });
        res.redirect('/admin/users?msg=added');
    } catch (err) {
        console.error('Error adding user by admin:', err);
        res.redirect('/admin/users?err=' + encodeURIComponent(err.message));
    }
});

app.post('/admin/users/edit/:id', isAuth, authorize('admin_divisi'), async (req, res) => {
    const user = req.session.user;
    const userId = req.params.id;
    const { full_name, email, password, position, is_active } = req.body;

    try {
        const check = await pool.query('SELECT * FROM users WHERE id=$1 AND department_id=$2', [userId, user.department_id]);
        if (!check.rows[0]) return res.redirect('/admin/users?err=Akses+ditolak');

        const old = check.rows[0];
        let query, values;

        if (password && password.trim()) {
            const hash = await argon2.hash(password);
            query = `UPDATE users SET full_name=$1, email=$2, password_hash=$3, position=$4, is_active=$5 WHERE id=$6`;
            values = [full_name, email.toLowerCase(), hash, position, is_active === 'true', userId];
        } else {
            query = `UPDATE users SET full_name=$1, email=$2, position=$3, is_active=$4 WHERE id=$5`;
            values = [full_name, email.toLowerCase(), position, is_active === 'true', userId];
        }

        await pool.query(query, values);
        await req.writeAudit('edit_user_admin', 'users', userId, old, { email, is_active });
        res.redirect('/admin/users?msg=updated');
    } catch (err) {
        console.error('Error editing user by admin:', err);
        res.redirect('/admin/users?err=' + encodeURIComponent(err.message));
    }
});

app.post('/admin/users/delete/:id', isAuth, authorize('admin_divisi'), async (req, res) => {
    const user = req.session.user;
    const userId = req.params.id;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const check = await client.query('SELECT * FROM users WHERE id=$1 AND department_id=$2', [userId, user.department_id]);
        if (!check.rows[0]) {
            await client.query('ROLLBACK');
            return res.status(403).json({ success: false, message: 'Akses ditolak' });
        }

        const targetUser = check.rows[0];

        await client.query('DELETE FROM audit_logs WHERE user_id = $1', [userId]);

        // Hapus semua notifikasi yang diterima user ini
        await client.query('DELETE FROM notifications WHERE recipient_user_id = $1', [userId]);

        const reportsRes = await client.query('SELECT id FROM daily_report WHERE user_id = $1', [userId]);
        let superFilesToDel = [];
        for (const r of reportsRes.rows) {
            // Hapus notifikasi, lampiran, dan detail keuangan laporan
            await client.query('DELETE FROM notifications WHERE reference_id = $1', [r.id]);
            await client.query('DELETE FROM daily_report_attachments WHERE report_id = $1', [r.id]);
            await client.query('DELETE FROM daily_report_finance_detail WHERE report_id = $1', [r.id]);

            superFilesToDel.push(...(await getReportFiles(r.id, 'daily_report', client)));
        }
        await client.query('DELETE FROM daily_report WHERE user_id = $1', [userId]);
        executeDeleteFiles(superFilesToDel);

        await req.writeAudit('deep_delete_user_admin', 'users', userId, targetUser, null);

        await client.query('DELETE FROM users WHERE id = $1', [userId]);

        await client.query('COMMIT');
        res.json({ success: true, message: 'User dan semua data terkait berhasil dihapus' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Deep delete error:', err);
        res.status(500).json({ success: false, message: 'Gagal menghapus user: ' + err.message });
    } finally {
        client.release();
    }
});

// ══════════════════════════════════════════════════════════════════════════════
// ROLE: SUPER ADMIN
// ══════════════════════════════════════════════════════════════════════════════

app.get('/sa/dashboard', isAuth, authorize('super_admin'), async (req, res) => {
    const user = req.session.user;
    const { date_from, date_to, status, dept_id, search } = req.query;

    try {
        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name,
                   (SELECT COALESCE(SUM(total_price), 0) FROM daily_report_finance_detail WHERE report_id = dr.id) as total_nominal
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            WHERE u.company_id = $1
        `;
        const params = [user.company_id];

        if (dept_id) { sql += ` AND dr.department_id = $${params.length + 1}`; params.push(dept_id); }
        if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
        if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
        if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
        if (search) { sql += ` AND u.full_name ILIKE $${params.length + 1}`; params.push(`%${search}%`); }

        sql += ` ORDER BY dr.report_date DESC, d.department_name, u.full_name`;
        const reports = await pool.query(sql, params);

        const stats = await pool.query(`
            SELECT d.department_name, dr.status, COUNT(*) as total
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON u.department_id = d.id
            WHERE u.company_id = $1
            GROUP BY d.department_name, dr.status
        `, [user.company_id]);

        const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);

        await renderWithNotif(res, 'superadmin/dashboard', {
            user,
            reports: reports.rows,
            stats: stats.rows,
            departments: depts.rows,
            filters: { date_from, date_to, status, dept_id, search }
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

app.get(['/sa/activity_log', '/sa/activity-log'], isAuth, authorize('super_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
        const notReported = await pool.query(`
            SELECT u.full_name, c.company_name, u.position
            FROM users u
            JOIN companies c ON u.company_id = c.id
            WHERE u.is_active = TRUE
              AND u.company_id = $1
              AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
              AND u.id NOT IN (
                SELECT user_id FROM daily_report 
                WHERE report_date = $2
              )
            ORDER BY u.full_name
        `, [user.company_id, todayStr]);

        await renderWithNotif(res, 'sda/activity_log', {
            user,
            notReported: notReported.rows,
            todayStr,
            activePage: 'activity_log'
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

app.get('/sa/employees', isAuth, authorize('super_admin'), async (req, res) => {
    const user = req.session.user;
    const { dept_id, search } = req.query;

    try {
        // Query to get all departments and employee counts for this company
        const deptStats = await pool.query(`
            SELECT d.id, d.department_name, 
                   (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.company_id = $1) as employee_count
            FROM departments d
            ORDER BY d.department_name ASC
        `, [user.company_id]);

        let employees = [];
        let selectedDept = null;

        if (dept_id) {
            const deptRes = await pool.query('SELECT * FROM departments WHERE id = $1', [dept_id]);
            selectedDept = deptRes.rows[0];

            let empSql = `
                SELECT u.*, r.role_name, d.department_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                JOIN departments d ON u.department_id = d.id
                WHERE u.company_id = $1 AND u.department_id = $2
            `;
            const empParams = [user.company_id, dept_id];

            if (search) {
                empSql += ` AND (u.full_name ILIKE $3 OR u.email ILIKE $3 OR u.position ILIKE $3)`;
                empParams.push(`%${search}%`);
            }

            empSql += ` ORDER BY u.full_name ASC`;
            const empRes = await pool.query(empSql, empParams);
            employees = empRes.rows;
        }

        await renderWithNotif(res, 'superadmin/employees', {
            user,
            deptStats: deptStats.rows,
            employees,
            selectedDept,
            filters: { dept_id, search },
            activePage: 'employees'
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});


// ══════════════════════════════════════════════════════════════════════════════
// ROLE: SUPER DUPER ADMIN
// ══════════════════════════════════════════════════════════════════════════════

app.get('/sda/dashboard', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const { date_from, date_to, status, dept_id, company_id: comp_id, search } = req.query;

    try {
        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name, c.id as comp_id,
                   (SELECT COALESCE(SUM(total_price), 0) FROM daily_report_finance_detail WHERE report_id = dr.id) as total_nominal
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1
        `;
        const params = [];

        if (comp_id) { sql += ` AND c.id = $${params.length + 1}`; params.push(comp_id); }
        if (dept_id) { sql += ` AND dr.department_id = $${params.length + 1}`; params.push(dept_id); }
        if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
        if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
        if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
        if (search) { sql += ` AND (u.full_name ILIKE $${params.length + 1} OR c.company_name ILIKE $${params.length + 1})`; params.push(`%${search}%`); }

        sql += ` ORDER BY dr.report_date DESC, c.company_name, d.department_name`;
        const reports = await pool.query(sql, params);

        let whereStats = "";
        let pStats = [];
        if (comp_id) { whereStats += ` AND c.id = $${pStats.length + 1}`; pStats.push(comp_id); }
        if (dept_id) { whereStats += ` AND dr.department_id = $${pStats.length + 1}`; pStats.push(dept_id); }
        if (status) { whereStats += ` AND dr.status = $${pStats.length + 1}`; pStats.push(status); }
        if (date_from) { whereStats += ` AND dr.report_date >= $${pStats.length + 1}`; pStats.push(date_from); }
        if (date_to) { whereStats += ` AND dr.report_date <= $${pStats.length + 1}`; pStats.push(date_to); }
        if (search) { whereStats += ` AND (u.full_name ILIKE $${pStats.length + 1} OR c.company_name ILIKE $${pStats.length + 1})`; pStats.push(`%${search}%`); }

        const companyStats = await pool.query(`
            SELECT COALESCE(c.company_name, 'N/A') as company_name, dr.status, COUNT(*) as total
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1 ${whereStats}
            GROUP BY c.company_name, dr.status
            ORDER BY c.company_name
        `, pStats);

        const statusStats = await pool.query(`
            SELECT dr.status, COUNT(*) as total 
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1 ${whereStats}
            GROUP BY dr.status
        `, pStats);

        let trendWhere = "WHERE report_date >= CURRENT_DATE - INTERVAL '30 days'";
        let trendParams = [];
        if (comp_id) { trendWhere += ` AND c.id = $${trendParams.length + 1}`; trendParams.push(comp_id); }
        if (dept_id) { trendWhere += ` AND dr.department_id = $${trendParams.length + 1}`; trendParams.push(dept_id); }

        const trend = await pool.query(`
            SELECT report_date, COUNT(*) as total
            FROM daily_report dr
            LEFT JOIN users u ON dr.user_id = u.id
            LEFT JOIN companies c ON u.company_id = c.id
            ${trendWhere}
            GROUP BY report_date ORDER BY report_date
        `, trendParams);

        const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
        const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);

        await renderWithNotif(res, 'sda/dashboard', {
            user,
            reports: reports.rows,
            companyStats: companyStats.rows,
            statusStats: statusStats.rows,
            trend: trend.rows,
            companies: companies.rows,
            departments: depts.rows,
            filters: { date_from, date_to, status, dept_id, company_id: comp_id, search }
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

app.get(['/sda/activity_log', '/sda/activity-log'], isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
        const notReported = await pool.query(`
            SELECT u.full_name, c.company_name, u.position
            FROM users u
            JOIN companies c ON u.company_id = c.id
            WHERE u.is_active = TRUE
              AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
              AND u.id NOT IN (
                SELECT user_id FROM daily_report 
                WHERE report_date = $1
              )
            ORDER BY c.company_name, u.full_name
        `, [todayStr]);

        await renderWithNotif(res, 'sda/activity_log', {
            user,
            notReported: notReported.rows,
            todayStr,
            activePage: 'activity_log'
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

// ── MASTER DATA: Companies (SDA only) ─────────────────────────────────────────
app.get('/sda/companies', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const companies = await pool.query(`SELECT * FROM companies ORDER BY company_name`);
        await renderWithNotif(res, 'sda/companies', { user, companies: companies.rows }, user.id);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/sda/companies/add', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { company_name, company_code, address } = req.body;
    try {
        await pool.query(`INSERT INTO companies (company_name, company_code, address) VALUES ($1,$2,$3)`, [company_name, company_code, address]);
        await req.writeAudit('create_company', 'companies', null, null, { company_name });
        res.redirect('/sda/companies?msg=added');
    } catch (err) {
        res.redirect('/sda/companies?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/companies/edit/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { company_name, company_code, address, is_active } = req.body;
    try {
        const old = await pool.query('SELECT * FROM companies WHERE id=$1', [req.params.id]);
        await pool.query(`UPDATE companies SET company_name=$1, company_code=$2, address=$3, is_active=$4 WHERE id=$5`,
            [company_name, company_code, address, is_active === 'true', req.params.id]);
        await req.writeAudit('edit_company', 'companies', req.params.id, old.rows[0], { company_name, is_active });
        res.redirect('/sda/companies?msg=updated');
    } catch (err) {
        res.redirect('/sda/companies?err=' + encodeURIComponent(err.message));
    }
});

// ── SDA EMPLOYEE VIEW ──────────────────────────────────────────────────────────
app.get('/sda/employees', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const { company_id, dept_id, search } = req.query;

    try {
        if (!company_id) {
            // Show all companies as selectable cards
            const companies = await pool.query(`
                SELECT c.*, 
                       (SELECT COUNT(*) FROM users u WHERE u.company_id = c.id) as employee_count
                FROM companies c 
                WHERE is_active = TRUE 
                ORDER BY company_name
            `);
            return await renderWithNotif(res, 'sda/employees', {
                user,
                companies: companies.rows,
                viewMode: 'company_list',
                activePage: 'sda_employees'
            }, user.id);
        }

        // Company is selected, show departments and employees
        const companyRes = await pool.query('SELECT * FROM companies WHERE id = $1', [company_id]);
        const selectedCompany = companyRes.rows[0];

        const deptStats = await pool.query(`
            SELECT d.id, d.department_name, 
                   (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.company_id = $1) as employee_count
            FROM departments d
            ORDER BY d.department_name ASC
        `, [company_id]);

        let employees = [];
        let selectedDept = null;

        if (dept_id) {
            const deptRes = await pool.query('SELECT * FROM departments WHERE id = $1', [dept_id]);
            selectedDept = deptRes.rows[0];

            let empSql = `
                SELECT u.*, r.role_name, d.department_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                JOIN departments d ON u.department_id = d.id
                WHERE u.company_id = $1 AND u.department_id = $2
            `;
            const empParams = [company_id, dept_id];

            if (search) {
                empSql += ` AND (u.full_name ILIKE $3 OR u.email ILIKE $3 OR u.position ILIKE $3)`;
                empParams.push(`%${search}%`);
            }

            empSql += ` ORDER BY u.full_name ASC`;
            const empRes = await pool.query(empSql, empParams);
            employees = empRes.rows;
        }

        await renderWithNotif(res, 'sda/employees', {
            user,
            selectedCompany,
            deptStats: deptStats.rows,
            employees,
            selectedDept,
            filters: { company_id, dept_id, search },
            viewMode: 'employee_data',
            activePage: 'sda_employees'
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

// ── MASTER DATA: Departments (SDA only) ───────────────────────────────────────
app.get('/sda/departments', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const depts = await pool.query(`
            SELECT d.*, 
                   ARRAY_AGG(c.company_name) as company_names,
                   ARRAY_AGG(c.id) as company_ids
            FROM departments d
            LEFT JOIN company_departments cd ON d.id = cd.department_id
            LEFT JOIN companies c ON cd.company_id = c.id
            GROUP BY d.id
            ORDER BY d.department_name
        `);
        const companies = await pool.query(`SELECT id, company_name FROM companies WHERE is_active = TRUE ORDER BY company_name`);
        await renderWithNotif(res, 'sda/departments', {
            user,
            departments: depts.rows.map(d => ({
                ...d,
                company_ids: d.company_ids ? d.company_ids.filter(id => id !== null) : [],
                company_names: d.company_names ? d.company_names.filter(name => name !== null) : []
            })),
            companies: companies.rows
        }, user.id);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/sda/departments/add', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { department_name, company_ids } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const nameUpper = department_name.toUpperCase();
        const rpt = await client.query(`INSERT INTO departments (department_name) VALUES ($1) RETURNING id`, [nameUpper]);
        const deptId = rpt.rows[0].id;

        if (company_ids) {
            const ids = Array.isArray(company_ids) ? company_ids : [company_ids];
            for (const cId of ids) {
                await client.query(`INSERT INTO company_departments (company_id, department_id) VALUES ($1, $2)`, [cId, deptId]);
            }
        }

        await req.writeAudit('create_dept', 'departments', deptId, null, { department_name: nameUpper, company_ids });
        await client.query('COMMIT');
        res.redirect('/sda/departments?msg=added');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error adding department:', err);
        res.redirect('/sda/departments?err=' + encodeURIComponent(err.message));
    } finally {
        client.release();
    }
});

// ── MASTER DATA: Users (SDA only) ─────────────────────────────────────────────
app.get('/sda/users', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    const { company_id, dept_id, search } = req.query;
    try {
        let sql = `
            SELECT u.*, r.role_name, c.company_name, d.department_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            LEFT JOIN companies c ON u.company_id = c.id
            LEFT JOIN departments d ON u.department_id = d.id
            WHERE 1=1
        `;
        const params = [];
        if (company_id) { sql += ` AND u.company_id = $${params.length + 1}`; params.push(company_id); }
        if (dept_id) { sql += ` AND u.department_id = $${params.length + 1}`; params.push(dept_id); }
        if (search) {
            sql += ` AND (u.full_name ILIKE $${params.length + 1} OR u.email ILIKE $${params.length + 1})`;
            params.push(`%${search}%`);
        }
        sql += ` ORDER BY c.company_name, d.department_name, u.full_name`;

        const users = await pool.query(sql, params);
        const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
        const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);
        const roles = await pool.query(`SELECT * FROM roles ORDER BY id`);

        await renderWithNotif(res, 'sda/users', {
            user,
            users: users.rows,
            companies: companies.rows,
            departments: depts.rows,
            roles: roles.rows,
            filters: { company_id, dept_id, search }
        }, user.id);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/sda/users/add', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { full_name, email, password, role_id, position, company_id, department_id } = req.body;
    try {
        const hash = await argon2.hash(password);
        const rpt = await pool.query(`
            INSERT INTO users (full_name, email, password_hash, role_id, position, company_id, department_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id
        `, [full_name, email.toLowerCase(), hash, role_id, position, company_id || null, department_id || null]);
        await req.writeAudit('create_user', 'users', rpt.rows[0].id, null, { email, role_id });
        res.redirect('/sda/users?msg=added');
    } catch (err) {
        console.error('Error adding user:', err);
        res.redirect('/sda/users?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/users/edit/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { full_name, email, password, role_id, position, company_id, department_id, is_active } = req.body;
    try {
        const old = await pool.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
        let query, values;

        const rId = role_id || null;
        const cId = company_id || null;
        const dId = department_id || null;

        if (password && password.trim()) {
            const hash = await argon2.hash(password);
            query = `UPDATE users SET full_name=$1, email=$2, password_hash=$3, role_id=$4, position=$5, company_id=$6, department_id=$7, is_active=$8 WHERE id=$9`;
            values = [full_name, email.toLowerCase(), hash, rId, position, cId, dId, is_active === 'true', req.params.id];
        } else {
            query = `UPDATE users SET full_name=$1, email=$2, role_id=$3, position=$4, company_id=$5, department_id=$6, is_active=$7 WHERE id=$8`;
            values = [full_name, email.toLowerCase(), rId, position, cId, dId, is_active === 'true', req.params.id];
        }

        await pool.query(query, values);
        await req.writeAudit('edit_user', 'users', req.params.id, old.rows[0], { role_id, is_active });
        res.redirect('/sda/users?msg=updated');
    } catch (err) {
        res.redirect('/sda/users?err=' + encodeURIComponent(err.message));
    }
});

// ── REPORT PERIODS (SDA) ───────────────────────────────────────────────────────
app.get('/sda/periods', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const periods = await pool.query(`
            SELECT rp.*, c.company_name FROM report_periods rp
            LEFT JOIN companies c ON rp.company_id=c.id
            ORDER BY rp.start_date DESC
        `);
        const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
        await renderWithNotif(res, 'sda/periods', { user, periods: periods.rows, companies: companies.rows }, user.id);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/sda/periods/add', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { period_name, company_id, start_date, end_date, deadline } = req.body;
    try {
        const rpt = await pool.query(`INSERT INTO report_periods (period_name, company_id, start_date, end_date, deadline) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
            [period_name, company_id || null, start_date, end_date, deadline || null]);
        await req.writeAudit('create_period', 'report_periods', rpt.rows[0].id, null, { period_name });
        res.redirect('/sda/periods?msg=added');
    } catch (err) {
        console.error('Error adding period:', err);
        res.redirect('/sda/periods?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/periods/edit/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { period_name, company_id, start_date, end_date, deadline, is_active } = req.body;
    try {
        await pool.query(`UPDATE report_periods SET period_name=$1, company_id=$2, start_date=$3, end_date=$4, deadline=$5, is_active=$6 WHERE id=$7`,
            [period_name, company_id || null, start_date, end_date, deadline || null, is_active === 'true', req.params.id]);
        res.redirect('/sda/periods?msg=updated');
    } catch (err) {
        res.redirect('/sda/periods?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/periods/delete/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    try {
        const old = await pool.query('SELECT * FROM report_periods WHERE id=$1', [req.params.id]);
        await pool.query('DELETE FROM report_periods WHERE id=$1', [req.params.id]);
        await req.writeAudit('delete_period', 'report_periods', req.params.id, old.rows[0], null);
        res.redirect('/sda/periods?msg=deleted');
    } catch (err) {
        res.redirect('/sda/periods?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/departments/edit/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { department_name, company_ids } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const nameUpper = department_name.toUpperCase();
        await client.query(`UPDATE departments SET department_name=$1 WHERE id=$2`,
            [nameUpper, req.params.id]);

        // Update company associations
        await client.query(`DELETE FROM company_departments WHERE department_id = $1`, [req.params.id]);
        if (company_ids) {
            const ids = Array.isArray(company_ids) ? company_ids : [company_ids];
            for (const cId of ids) {
                await client.query(`INSERT INTO company_departments (company_id, department_id) VALUES ($1, $2)`, [cId, req.params.id]);
            }
        }

        await client.query('COMMIT');
        res.redirect('/sda/departments?msg=updated');
    } catch (err) {
        await client.query('ROLLBACK');
        res.redirect('/sda/departments?err=' + encodeURIComponent(err.message));
    } finally {
        client.release();
    }
});

app.post('/sda/departments/delete/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    try {
        const old = await pool.query('SELECT * FROM departments WHERE id=$1', [req.params.id]);
        await pool.query('DELETE FROM departments WHERE id=$1', [req.params.id]);
        await req.writeAudit('delete_dept', 'departments', req.params.id, old.rows[0], null);
        res.redirect('/sda/departments?msg=deleted');
    } catch (err) {
        res.redirect('/sda/departments?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/companies/delete/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    try {
        await pool.query('DELETE FROM companies WHERE id=$1', [req.params.id]);
        await req.writeAudit('delete_company', 'companies', req.params.id, null, null);
        res.redirect('/sda/companies?msg=deleted');
    } catch (err) {
        res.redirect('/sda/companies?err=' + encodeURIComponent(err.message));
    }
});

app.post('/sda/users/delete/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const userId = req.params.id;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const old = await client.query('SELECT * FROM users WHERE id=$1', [userId]);
        if (!old.rows[0]) {
            await client.query('ROLLBACK');
            return res.redirect('/sda/users?err=User+tidak+ditemukan');
        }

        await client.query('DELETE FROM audit_logs WHERE user_id = $1', [userId]);

        // Hapus semua notifikasi yang diterima user ini
        await client.query('DELETE FROM notifications WHERE recipient_user_id = $1', [userId]);

        const sdaReportsRes = await client.query('SELECT id FROM daily_report WHERE user_id = $1', [userId]);
        let sdaFilesToDel = [];
        for (const r of sdaReportsRes.rows) {
            // Hapus notifikasi, lampiran, dan detail keuangan laporan
            await client.query('DELETE FROM notifications WHERE reference_id = $1', [r.id]);
            await client.query('DELETE FROM daily_report_attachments WHERE report_id = $1', [r.id]);
            await client.query('DELETE FROM daily_report_finance_detail WHERE report_id = $1', [r.id]);

            sdaFilesToDel.push(...(await getReportFiles(r.id, 'daily_report', client)));
        }
        await client.query('DELETE FROM daily_report WHERE user_id = $1', [userId]);
        executeDeleteFiles(sdaFilesToDel);

        // Catat audit SEBELUM menghapus user (agar FK user_id di audit_logs masih valid jika hapus diri sendiri)
        await req.writeAudit('deep_delete_user_sda', 'users', userId, old.rows[0], null);

        await client.query('DELETE FROM users WHERE id = $1', [userId]);



        await client.query('COMMIT');
        res.redirect('/sda/users?msg=deleted');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('SDA Deep delete error:', err);
        res.redirect('/sda/users?err=' + encodeURIComponent('Gagal hapus: ' + err.message));
    } finally {
        client.release();
    }
});

app.get('/sda/report/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const rpt = await pool.query(`
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE dr.id = $1
        `, [req.params.id]);

        if (!rpt.rows[0]) return res.redirect('/sda/dashboard');
        const report = rpt.rows[0];

        let financeItems = [];
        if (isFinanceDept(report.department_name) || isProduksiDept(report.department_name)) {
            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            financeItems = fd.rows;
        }

        const attRes = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
        const attachments = attRes.rows;

        await renderWithNotif(res, 'sda/report_detail', { user, report, financeItems, attachments }, user.id);
    } catch (err) {
        console.error(err);
        res.redirect('/sda/dashboard?err=' + encodeURIComponent(err.message));
    }
});

app.get('/sda/api/check-high-value', isAuth, authorize('super_duper_admin'), async (req, res) => {
    try {
        const rpt = await pool.query(`
            SELECT id as notif_id, message, reference_id as report_id
            FROM notifications
            WHERE recipient_user_id = $1 
              AND type = 'high_value'
              AND is_read = FALSE
            ORDER BY created_at DESC
            LIMIT 1
        `, [req.session.user.id]);
        res.json({ success: true, data: rpt.rows[0] || null });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ── TANYA SOLUSI (Ask Director) ───────────────────────────────────────────────
app.post('/report/ask-director/:id', isAuth, async (req, res) => {
    const reportId = req.params.id;
    const user = req.session.user;
    try {
        // Mark report as asked (any authorized role may trigger this)
        await pool.query(`UPDATE daily_report SET is_asked_director = TRUE WHERE id = $1`, [reportId]);

        // Get report details for notification message
        const rptRes = await pool.query(`
            SELECT dr.task_description, dr.issue, u.full_name, c.company_name, d.department_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN companies c ON u.company_id = c.id
            LEFT JOIN departments d ON dr.department_id = d.id
            WHERE dr.id = $1
        `, [reportId]);
        const rpt = rptRes.rows[0];

        // Send notification to ALL super_duper_admin
        const sdaUsers = await pool.query(`
            SELECT id FROM users WHERE role_id = (SELECT id FROM roles WHERE role_name = 'super_duper_admin') AND is_active = TRUE
        `);

        for (const sda of sdaUsers.rows) {
            await pool.query(`
                INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id)
                VALUES ($1, 'system', $2, 'urgent_solution', $3)
            `, [
                sda.id,
                `🔴 [URGENT] ${rpt.full_name} (${rpt.department_name} - ${rpt.company_name}) meminta solusi untuk laporan: "${(rpt.issue || rpt.task_description || '').substring(0, 80)}..."`,
                reportId
            ]);
        }

        res.json({ success: true, message: 'Permintaan solusi telah dikirim ke Director' });
    } catch (err) {
        console.error('Ask director error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── SDA URGENT PAGE ───────────────────────────────────────────────────────────
app.get('/sda/urgent', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const user = req.session.user;
    try {
        const urgentReports = await pool.query(`
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name,
                   dr.is_asked_director,
                   CASE WHEN (dr.director_solution IS NOT NULL AND dr.director_solution != '') THEN TRUE ELSE FALSE END as is_solved
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE dr.is_asked_director = TRUE
            ORDER BY 
                CASE WHEN (dr.director_solution IS NULL OR dr.director_solution = '') THEN 0 ELSE 1 END ASC,
                dr.created_at DESC
        `);

        // Count unsolved
        const unsolvedCount = urgentReports.rows.filter(r => !r.is_solved).length;

        await renderWithNotif(res, 'sda/urgent', {
            user,
            urgentReports: urgentReports.rows,
            unsolvedCount,
            activePage: 'urgent',
            msg: req.query.msg
        }, user.id);
    } catch (err) {
        console.error(err);
        res.status(500).send(err.message);
    }
});

// ── SDA: Give Solution (from urgent page) ────────────────────────────────────
app.post('/sda/report/give-solution/:id', isAuth, authorize('super_duper_admin'), async (req, res) => {
    const { director_solution, manager_note } = req.body;
    const reportId = req.params.id;
    try {
        await pool.query(`
            UPDATE daily_report SET director_solution = $1, manager_note = $2 WHERE id = $3
        `, [director_solution, manager_note, reportId]);

        // Notify the report owner
        const rptRes = await pool.query(`SELECT user_id FROM daily_report WHERE id = $1`, [reportId]);
        if (rptRes.rows[0]) {
            await pool.query(`
                INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id)
                VALUES ($1, 'admin', $2, 'laporan_direview', $3)
            `, [rptRes.rows[0].user_id, `✅ Director telah memberikan solusi untuk laporan Anda (ID #${reportId}).`, reportId]);
        }

        res.redirect('/sda/urgent?msg=solved');
    } catch (err) {
        res.redirect('/sda/urgent?msg=error&err=' + encodeURIComponent(err.message));
    }
});

// ── NOTIFIKASI ─────────────────────────────────────────────────────────────────
app.get('/notif/read/:id', isAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE notifications SET is_read=TRUE WHERE id=$1 AND recipient_user_id=$2`, [req.params.id, req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post('/notif/read-all', isAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE notifications SET is_read=TRUE WHERE recipient_user_id=$1`, [req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ── KEAMANAN (SECURITY) ───────────────────────────────────────────────────────
app.get('/security', isAnyAuth, async (req, res) => {
    try {
        const table = req.session.user.isDirector ? 'director_users' : 'users';
        const result = await pool.query(`SELECT mfa_enabled FROM ${table} WHERE id = $1`, [req.session.user.id]);

        const renderFn = req.session.user.isDirector ? renderWithNotifDirector : renderWithNotif;

        renderFn(res, 'security', {
            user: req.session.user,
            activePage: 'security',
            mfaEnabled: result.rows[0].mfa_enabled,
            msg: req.query.msg,
            err: req.query.err
        }, req.session.user.id);
    } catch (err) {
        res.redirect(req.session.user.isDirector ? '/director/dashboard' : '/dashboard');
    }
});

app.get('/security/mfa/setup', isAnyAuth, async (req, res) => {
    try {
        let secretBase32 = req.session.tempMfaSecret;
        let otpauthUrl = req.session.tempMfaUrl;

        if (!secretBase32 || !otpauthUrl) {
            const secret = speakeasy.generateSecret({
                name: `Daily Report System (${req.session.user.email})`
            });
            secretBase32 = secret.base32;
            otpauthUrl = secret.otpauth_url;
            req.session.tempMfaSecret = secretBase32;
            req.session.tempMfaUrl = otpauthUrl;
        }

        const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);

        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

        const renderFn = req.session.user.isDirector ? renderWithNotifDirector : renderWithNotif;
        renderFn(res, 'setup_mfa', {
            user: req.session.user,
            activePage: 'security',
            qrCodeUrl,
            secret: secretBase32
        }, req.session.user.id);
    } catch (err) {
        res.redirect('/security?err=' + encodeURIComponent(err.message));
    }
});

app.post('/security/mfa/enable', isAnyAuth, async (req, res) => {
    let { token } = req.body;
    token = token ? token.replace(/\s+/g, '') : '';
    const secret = req.session.tempMfaSecret;

    if (!secret) return res.redirect('/security?err=session_expired');

    // Fetch real time from NTP
    const realTime = await getRealTime();
    const serverTime = Math.floor(Date.now() / 1000);

    console.log('[MFA ENABLE DEBUG]');
    console.log('  Token received :', token);
    console.log('  Secret (first 8):', secret ? secret.substring(0, 8) + '...' : 'NONE');
    console.log('  Server time (s) :', serverTime, '=', new Date(serverTime * 1000).toISOString());
    console.log('  NTP real time(s):', realTime, '=', new Date(realTime * 1000).toISOString());

    // Try verifying with NTP time
    let isValid = speakeasy.totp.verify({ secret, encoding: 'base32', token, time: realTime, window: 10 });
    console.log('  isValid (NTP time) :', isValid);

    // Fallback: try with server's own clock
    if (!isValid) {
        isValid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 10 });
        console.log('  isValid (server clock):', isValid);
    }

    if (isValid) {
        try {
            const table = req.session.user.isDirector ? 'director_users' : 'users';
            await pool.query(`UPDATE ${table} SET mfa_secret = $1, mfa_enabled = TRUE WHERE id = $2`, [secret, req.session.user.id]);
            delete req.session.tempMfaSecret;
            delete req.session.tempMfaUrl;
            res.redirect('/security?msg=mfa_enabled');
        } catch (err) {
            res.redirect('/security?err=' + encodeURIComponent(err.message));
        }
    } else {
        console.log('  [MFA ENABLE] FAILED - token did not match any window');
        res.redirect('/security/mfa/setup?err=invalid_token');
    }
});


app.post('/security/mfa/disable', isAnyAuth, async (req, res) => {
    try {
        let { token } = req.body;
        token = token ? token.replace(/\s+/g, '') : '';
        const table = req.session.user.isDirector ? 'director_users' : 'users';

        const result = await pool.query(`SELECT mfa_secret FROM ${table} WHERE id = $1`, [req.session.user.id]);
        const secret = result.rows[0]?.mfa_secret;

        if (!secret) return res.redirect('/security?err=MFA+tidak+aktif');

        // Fetch real time to fix TOTP when server clock is wrong (set to 2026)
        const realTime = await getRealTime();

        let isValid = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            time: realTime,
            window: 2
        });

        if (!isValid) return res.redirect('/security?err=Kode+verifikasi+salah');

        await pool.query(`UPDATE ${table} SET mfa_secret = NULL, mfa_enabled = FALSE WHERE id = $1`, [req.session.user.id]);
        res.redirect('/security?msg=mfa_disabled');
    } catch (err) {
        res.redirect('/security?err=' + encodeURIComponent(err.message));
    }
});

// ── EXPORT EXCEL ───────────────────────────────────────────────────────────────
app.get('/export/excel', isAuth, async (req, res) => {
    const user = req.session.user;
    const { date_from, date_to, status, dept_id, comp_id } = req.query;

    try {
        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1
        `;
        const params = [];

        if (user.role_name === 'user') {
            sql += ` AND dr.user_id = $${params.length + 1}`; params.push(user.id);
        } else if (user.role_name === 'admin_divisi') {
            sql += ` AND dr.department_id = $${params.length + 1} AND u.company_id = $${params.length + 2}`;
            params.push(user.department_id, user.company_id);
        } else if (user.role_name === 'super_admin') {
            sql += ` AND c.id = $${params.length + 1}`; params.push(user.company_id);
        }

        if (comp_id && user.role_name === 'super_duper_admin') { sql += ` AND c.id = $${params.length + 1}`; params.push(comp_id); }
        if (dept_id) { sql += ` AND dr.department_id = $${params.length + 1}`; params.push(dept_id); }
        if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
        if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
        if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
        sql += ` ORDER BY dr.report_date DESC, u.full_name`;

        const reports = await pool.query(sql, params);

        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet('Daily Report');

        sheet.addRow(['No', 'Tanggal', 'Nama', 'Perusahaan', 'Divisi', 'Jabatan', 'Tugas', 'Kendala', 'Solusi', 'Hasil', 'Status', 'Catatan Manager']);
        sheet.getRow(1).font = { bold: true };

        reports.rows.forEach((r, i) => {
            const row = [
                i + 1, r.report_date, r.full_name, r.company_name, r.department_name,
                r.position, r.task_description, r.issue, r.solution, r.result, r.status, r.manager_note
            ];
            sheet.addRow(row);
        });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="daily-report-${Date.now()}.xlsx"`);
        await workbook.xlsx.write(res);
        res.end();
    } catch (err) {
        console.error(err);
        res.status(500).send('Export gagal: ' + err.message);
    }
});

// ── EXPORT PDF ─────────────────────────────────────────────────────────────────
app.get('/export/pdf', isAuth, async (req, res) => {
    const user = req.session.user;
    const { date_from, date_to, status } = req.query;

    try {
        let sql = `
            SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
            FROM daily_report dr
            JOIN users u ON dr.user_id = u.id
            LEFT JOIN departments d ON dr.department_id = d.id
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE 1=1
        `;
        const params = [];
        if (user.role_name === 'user') { sql += ` AND dr.user_id = $${params.length + 1}`; params.push(user.id); }
        else if (user.role_name === 'admin_divisi') { sql += ` AND dr.department_id = $${params.length + 1}`; params.push(user.department_id); }
        else if (user.role_name === 'super_admin') { sql += ` AND u.company_id = $${params.length + 1}`; params.push(user.company_id); }
        if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
        if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
        if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
        sql += ` ORDER BY dr.report_date DESC LIMIT 200`;

        const reports = await pool.query(sql, params);

        const doc = new PDFDocument({ margin: 40, size: 'A4', layout: 'landscape' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="daily-report-${Date.now()}.pdf"`);
        doc.pipe(res);

        doc.fontSize(16).text('DAILY REPORT', { align: 'center' });
        doc.fontSize(10).text(`Diekspor: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}`, { align: 'center' });
        doc.moveDown();

        reports.rows.forEach((r, i) => {
            doc.fontSize(10).font('Helvetica-Bold').text(`${i + 1}. ${r.full_name} | ${r.company_name} | ${r.department_name} | ${r.report_date}`);
            doc.font('Helvetica').text(`   Status: ${r.status}`);
            doc.text(`   Tugas: ${r.task_description || '-'}`);
            if (r.issue) doc.text(`   Kendala: ${r.issue}`);
            if (r.solution) doc.text(`   Solusi: ${r.solution}`);
            if (r.manager_note) doc.text(`   Catatan Manager: ${r.manager_note}`);
            doc.moveDown(0.5);
        });

        doc.end();
    } catch (err) {
        console.error(err);
        res.status(500).send('PDF export gagal: ' + err.message);
    }
});

// ── LAMPIRAN ───────────────────────────────────────────────────────────────────
app.get('/attachment/:filename', isAuth, (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    if (filename.includes('..') || filename.includes('/')) {
        return res.status(400).send('Invalid filename');
    }
    const filePath = path.join(__dirname, 'public', 'uploads', filename);
    if (fs.existsSync(filePath)) {
        const ext = path.extname(filename).toLowerCase();
        if (ext === '.pdf') {
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
        }
        res.sendFile(filePath);
    } else {
        const redirectUrl = req.session.user.role_name === 'super_duper_admin' ? '/sda/dashboard' : '/dashboard';
        res.redirect(`${redirectUrl}?err=file_not_found`);
    }
});

app.get('/attachment/view/:filename', isAuth, async (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    try {
        const resPath = await pool.query('SELECT report_id FROM daily_report_attachments WHERE attachment_path LIKE $1', [`%${filename}`]);
        let attachments = [];
        let reportId = null;

        if (resPath.rows[0]) {
            reportId = resPath.rows[0].report_id;
            const allAtt = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id = $1', [reportId]);
            attachments = allAtt.rows;
        }

        res.render('attachment_view', { filename, attachments, reportId, user: req.session.user });
    } catch (err) {
        console.error(err);
        res.render('attachment_view', { filename, attachments: [], user: req.session.user });
    }
});

// ── CRON JOB: Reminder laporan harian ─────────────────────────────────────────
cron.schedule('0 17 * * 1-6', async () => {
    console.log('[CRON] Checking users who have not submitted reports today...');
    try {
        const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());

        const unreportedUsers = await pool.query(`
            SELECT u.id as user_id, u.full_name, u.department_id, u.company_id
            FROM users u
            JOIN report_periods rp ON rp.company_id = u.company_id
            WHERE u.is_active = TRUE
              AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
              AND rp.is_active = TRUE
              AND CURRENT_DATE BETWEEN rp.start_date AND rp.end_date
              AND u.id NOT IN (
                SELECT user_id FROM daily_report 
                WHERE report_date = $1 AND status IN ('submitted', 'approved')
              )
        `, [today]);

        for (const u of unreportedUsers.rows) {
            const admins = await pool.query(`
                SELECT id FROM users
                WHERE department_id = $1 AND company_id = $2
                  AND role_id = (SELECT id FROM roles WHERE role_name = 'admin_divisi')
                  AND is_active = TRUE
            `, [u.department_id, u.company_id]);

            for (const admin of admins.rows) {
                await pool.query(`
                    INSERT INTO notifications (recipient_user_id, sender_type, message, type)
                    VALUES ($1, 'system', $2, 'belum_lapor')
                `, [admin.id, `${u.full_name} belum mengisi laporan harian untuk tanggal ${today}.`]);
            }
        }

        console.log(`[CRON] Sent reminders for ${unreportedUsers.rows.length} users.`);
    } catch (err) {
        console.error('[CRON] Error:', err.message);
    }
});


// ── NOTIFICATION ROUTES ───────────────────────────────────────────────────────
app.get('/notif/read/:id', isAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE notifications SET is_read = TRUE WHERE id = $1 AND recipient_user_id = $2`, [req.params.id, req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Read notif error:', err);
        res.status(500).json({ success: false });
    }
});

app.post('/notif/read-all', isAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE notifications SET is_read = TRUE WHERE recipient_user_id = $1`, [req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Read all notif error:', err);
        res.status(500).json({ success: false });
    }
});

// Director Notif Routes
app.get('/director/notif/read/:id', isDirectorAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE director_notifications SET is_read = TRUE WHERE id = $1 AND recipient_user_id = $2`, [req.params.id, req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Read director notif error:', err);
        res.status(500).json({ success: false });
    }
});

app.post('/director/notif/read-all', isDirectorAuth, async (req, res) => {
    try {
        await pool.query(`UPDATE director_notifications SET is_read = TRUE WHERE recipient_user_id = $1`, [req.session.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Read all director notif error:', err);
        res.status(500).json({ success: false });
    }
});


// ── MOBILE API ROUTES ──────────────────────────────────────────────────────────
const apiRouter = require('./routes/api')(pool, upload, {
    isFinanceDept, isProduksiDept, getNotifCount, getNotifications,
    checkAndNotifyHighValueReport, getReportFiles, executeDeleteFiles
});
app.use('/api', apiRouter);

// ── ERROR HANDLER ──────────────────────────────────────────────────────────────

app.use((req, res) => {
    res.status(404).render('404', { user: req.session?.user || null });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    if (res.headersSent) return;
    res.status(500).render('500', { user: req.session?.user || null, error: err.message });
});

// ── START SERVER ───────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`=========================================`);
        console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
        console.log(`=========================================`);
    });

// Export app untuk Vercel
module.exports = app;