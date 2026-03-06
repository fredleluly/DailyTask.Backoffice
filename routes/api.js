/**
 * routes/api.js — Mobile REST API for DailyTask
 * All endpoints return JSON. Auth via session cookies.
 */
const express = require('express');
const router = express.Router();
const argon2 = require('argon2');
const bcrypt = require('bcryptjs');

module.exports = function (pool, upload, helpers) {
    const { isFinanceDept, isProduksiDept, getNotifCount, getNotifications,
            checkAndNotifyHighValueReport, getReportFiles, executeDeleteFiles } = helpers;

    // ── API Auth Middleware (JSON responses) ─────────────────────────────────
    function apiAuth(req, res, next) {
        if (req.session && req.session.user) return next();
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    function apiAuthorize(...roles) {
        return (req, res, next) => {
            if (!req.session.user) return res.status(401).json({ success: false, message: 'Unauthorized' });
            if (!roles.includes(req.session.user.role_name)) {
                return res.status(403).json({ success: false, message: 'Forbidden' });
            }
            next();
        };
    }

    // ══════════════════════════════════════════════════════════════════════════
    // AUTH
    // ══════════════════════════════════════════════════════════════════════════

    router.post('/login', async (req, res) => {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email dan password wajib diisi.' });
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
            if (!user) return res.status(401).json({ success: false, message: 'Email atau password salah!' });

            let isMatch = false;
            if (user.password_hash.startsWith('$argon2')) {
                isMatch = await argon2.verify(user.password_hash, password);
            } else if (user.password_hash.startsWith('$2')) {
                isMatch = await bcrypt.compare(password, user.password_hash);
            } else {
                isMatch = (user.password_hash === password);
            }

            if (!isMatch) return res.status(401).json({ success: false, message: 'Email atau password salah!' });

            // Check MFA
            if (user.mfa_enabled) {
                req.session.tempUser = {
                    id: user.id, full_name: user.full_name, email: user.email,
                    role_name: user.role_name, company_id: user.company_id,
                    company_name: user.company_name, department_id: user.department_id,
                    department_name: user.department_name, position: user.position,
                    isDirector: false
                };
                return res.json({ success: true, mfa_required: true, message: 'MFA verification required' });
            }

            req.session.user = {
                id: user.id, full_name: user.full_name, email: user.email,
                role_name: user.role_name, company_id: user.company_id,
                company_name: user.company_name, department_id: user.department_id,
                department_name: user.department_name, position: user.position,
                isDirector: false
            };

            res.json({
                success: true,
                user: req.session.user
            });
        } catch (err) {
            console.error('[API] Login error:', err);
            res.status(500).json({ success: false, message: 'Terjadi kesalahan sistem.' });
        }
    });

    router.post('/verify-mfa', async (req, res) => {
        const { token } = req.body;
        const tempUser = req.session.tempUser;
        if (!tempUser) return res.status(400).json({ success: false, message: 'No pending MFA session' });

        try {
            const speakeasy = require('speakeasy');
            const table = tempUser.isDirector ? 'director_users' : 'users';
            const secretRes = await pool.query(`SELECT mfa_secret FROM ${table} WHERE id = $1`, [tempUser.id]);
            const secret = secretRes.rows[0]?.mfa_secret;
            if (!secret) return res.status(400).json({ success: false, message: 'MFA not configured' });

            let isValid = speakeasy.totp.verify({ secret, encoding: 'base32', token: (token || '').replace(/\s+/g, ''), window: 2 });

            if (!isValid) return res.status(401).json({ success: false, message: 'Kode verifikasi salah' });

            req.session.user = { ...tempUser };
            delete req.session.tempUser;

            res.json({ success: true, user: req.session.user });
        } catch (err) {
            console.error('[API] MFA error:', err);
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/logout', (req, res) => {
        req.session = null;
        res.json({ success: true });
    });

    router.get('/me', apiAuth, (req, res) => {
        res.json({ success: true, user: req.session.user });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // NOTIFICATIONS
    // ══════════════════════════════════════════════════════════════════════════

    router.get('/notifications', apiAuth, async (req, res) => {
        try {
            const count = await getNotifCount(req.session.user.id);
            const notifications = await getNotifications(req.session.user.id, 50);
            res.json({ success: true, count, notifications });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/notifications/:id/read', apiAuth, async (req, res) => {
        try {
            await pool.query(`UPDATE notifications SET is_read=TRUE WHERE id=$1 AND recipient_user_id=$2`, [req.params.id, req.session.user.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false }); }
    });

    router.post('/notifications/read-all', apiAuth, async (req, res) => {
        try {
            await pool.query(`UPDATE notifications SET is_read=TRUE WHERE recipient_user_id=$1`, [req.session.user.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false }); }
    });

    // ══════════════════════════════════════════════════════════════════════════
    // USER REPORTS
    // ══════════════════════════════════════════════════════════════════════════

    router.get('/reports', apiAuth, async (req, res) => {
        const user = req.session.user;
        const { date_from, date_to, status, limit } = req.query;
        try {
            let sql = `
                SELECT dr.*, d.department_name
                FROM daily_report dr
                LEFT JOIN departments d ON dr.department_id = d.id
                WHERE dr.user_id = $1
            `;
            const params = [user.id];
            if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
            if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
            if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
            sql += ` ORDER BY dr.report_date DESC, dr.created_at DESC LIMIT $${params.length + 1}`;
            params.push(parseInt(limit) || 30);

            const reports = await pool.query(sql, params);

            // Stats
            const statsRes = await pool.query(`
                SELECT status, COUNT(*) as total FROM daily_report WHERE user_id = $1 GROUP BY status
            `, [user.id]);

            res.json({ success: true, reports: reports.rows, stats: statsRes.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/reports/:id', apiAuth, async (req, res) => {
        const user = req.session.user;
        try {
            const rpt = await pool.query(`
                SELECT dr.*, d.department_name
                FROM daily_report dr
                LEFT JOIN departments d ON dr.department_id = d.id
                WHERE dr.id = $1 AND dr.user_id = $2
            `, [req.params.id, user.id]);

            if (!rpt.rows[0]) return res.status(404).json({ success: false, message: 'Report not found' });
            const report = rpt.rows[0];

            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            const att = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);

            res.json({ success: true, report, financeItems: fd.rows, attachments: att.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/reports', apiAuth, upload.array('attachments', 10), async (req, res) => {
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
                await pool.query(`INSERT INTO daily_report_attachments (report_id, attachment_path, file_type) VALUES ($1, $2, $3)`,
                    [reportId, '/uploads/' + file.filename, file.mimetype]);
            }

            // Finance detail
            if (isFinanceDept(user.department_name)) {
                const items = Array.isArray(req.body.item_name) ? req.body.item_name : (req.body.item_name ? [req.body.item_name] : []);
                const qtys = Array.isArray(req.body.qty) ? req.body.qty : (req.body.qty ? [req.body.qty] : []);
                const prices = Array.isArray(req.body.unit_price) ? req.body.unit_price : (req.body.unit_price ? [req.body.unit_price] : []);
                for (let i = 0; i < items.length; i++) {
                    if (items[i]) {
                        const qty = parseFloat(qtys[i]) || 0;
                        const unitPrice = parseFloat(prices[i]) || 0;
                        await pool.query(`INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price) VALUES ($1,$2,$3,$4,$5)`,
                            [reportId, items[i], qty, unitPrice, qty * unitPrice]);
                    }
                }
            }

            if (isProduksiDept(user.department_name)) {
                const qtyProd = parseFloat(req.body.qty) || 0;
                if (qtyProd > 0) {
                    await pool.query(`INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price) VALUES ($1, 'Hasil Produksi', $2, 0, 0)`, [reportId, qtyProd]);
                }
            }

            if (status === 'submitted') await checkAndNotifyHighValueReport(reportId, user);

            res.json({ success: true, reportId, message: 'Laporan berhasil dibuat' });
        } catch (err) {
            console.error('[API] Create report error:', err);
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.put('/reports/:id', apiAuth, upload.array('attachments', 10), async (req, res) => {
        const user = req.session.user;
        const { task_description, issue, solution, result, status_action } = req.body;
        const status = status_action === 'submit' ? 'submitted' : 'draft';
        const reportId = req.params.id;

        try {
            const existing = await pool.query(`SELECT * FROM daily_report WHERE id=$1 AND user_id=$2`, [reportId, user.id]);
            if (!existing.rows[0]) return res.status(404).json({ success: false, message: 'Report not found' });
            if (existing.rows[0].status === 'approved') return res.status(400).json({ success: false, message: 'Report already approved' });

            const oldVal = existing.rows[0];
            const attachments = req.files || [];
            const firstAttachment = attachments.length > 0 ? '/uploads/' + attachments[0].filename : oldVal.attachment_path;

            await pool.query(`UPDATE daily_report SET task_description=$1, issue=$2, solution=$3, result=$4, status=$5, attachment_path=$6 WHERE id=$7 AND user_id=$8`,
                [task_description, issue, solution, result, status, firstAttachment, reportId, user.id]);

            if (attachments.length > 0) {
                const oldFiles = await getReportFiles(reportId, 'daily_report', pool);
                await pool.query('DELETE FROM daily_report_attachments WHERE report_id=$1', [reportId]);
                executeDeleteFiles(oldFiles);
                for (const file of attachments) {
                    await pool.query(`INSERT INTO daily_report_attachments (report_id, attachment_path, file_type) VALUES ($1, $2, $3)`,
                        [reportId, '/uploads/' + file.filename, file.mimetype]);
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
                        await pool.query(`INSERT INTO daily_report_finance_detail (report_id, item_name, qty, unit_price, total_price) VALUES ($1,$2,$3,$4,$5)`,
                            [reportId, items[i], qty, up, qty * up]);
                    }
                }
            }

            if (status === 'submitted') await checkAndNotifyHighValueReport(reportId, user);
            res.json({ success: true, message: 'Laporan berhasil diupdate' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.delete('/reports/:id', apiAuth, async (req, res) => {
        const user = req.session.user;
        try {
            const check = await pool.query(`SELECT * FROM daily_report WHERE id=$1 AND user_id=$2`, [req.params.id, user.id]);
            if (!check.rows[0]) return res.status(404).json({ success: false, message: 'Report not found' });

            const filesToDel = await getReportFiles(req.params.id, 'daily_report', pool);
            await pool.query('DELETE FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            await pool.query('DELETE FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
            await pool.query('DELETE FROM notifications WHERE reference_id=$1', [req.params.id]);
            await pool.query('DELETE FROM daily_report WHERE id=$1', [req.params.id]);
            executeDeleteFiles(filesToDel);

            res.json({ success: true, message: 'Laporan berhasil dihapus' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/reports/:id/approve', apiAuth, async (req, res) => {
        const user = req.session.user;
        try {
            const check = await pool.query(`SELECT * FROM daily_report WHERE id=$1 AND user_id=$2`, [req.params.id, user.id]);
            if (!check.rows[0]) return res.status(403).json({ success: false, message: 'Akses ditolak' });
            if (check.rows[0].status === 'approved') return res.json({ success: true, message: 'Sudah di-approve' });

            await pool.query(`UPDATE daily_report SET status='approved' WHERE id=$1`, [req.params.id]);
            res.json({ success: true, message: 'Laporan berhasil di-approve' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/reports/:id/ask-director', apiAuth, async (req, res) => {
        try {
            await pool.query(`UPDATE daily_report SET is_asked_director = TRUE WHERE id = $1`, [req.params.id]);
            const rptRes = await pool.query(`
                SELECT dr.task_description, dr.issue, u.full_name, c.company_name, d.department_name
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
                LEFT JOIN companies c ON u.company_id = c.id LEFT JOIN departments d ON dr.department_id = d.id
                WHERE dr.id = $1
            `, [req.params.id]);
            const rpt = rptRes.rows[0];
            const sdaUsers = await pool.query(`SELECT id FROM users WHERE role_id = (SELECT id FROM roles WHERE role_name = 'super_duper_admin') AND is_active = TRUE`);
            for (const sda of sdaUsers.rows) {
                await pool.query(`INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id) VALUES ($1, 'system', $2, 'urgent_solution', $3)`,
                    [sda.id, `🔴 [URGENT] ${rpt.full_name} meminta solusi: "${(rpt.issue || rpt.task_description || '').substring(0, 80)}..."`, req.params.id]);
            }
            res.json({ success: true, message: 'Permintaan solusi telah dikirim' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN DIVISI
    // ══════════════════════════════════════════════════════════════════════════

    router.get('/admin/reports', apiAuth, apiAuthorize('admin_divisi', 'super_admin', 'super_duper_admin'), async (req, res) => {
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
            if (search) { sql += ` AND u.full_name ILIKE $${params.length + 1}`; params.push(`%${search}%`); }
            sql += ` ORDER BY dr.report_date DESC, u.full_name`;

            const reports = await pool.query(sql, params);
            const statsRes = await pool.query(`
                SELECT status, COUNT(*) as total FROM daily_report dr
                JOIN users u ON dr.user_id = u.id
                WHERE u.department_id = $1 AND u.company_id = $2 GROUP BY status
            `, [user.department_id, user.company_id]);

            res.json({ success: true, reports: reports.rows, stats: statsRes.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/admin/reports/:id', apiAuth, apiAuthorize('admin_divisi', 'super_admin', 'super_duper_admin'), async (req, res) => {
        try {
            const rpt = await pool.query(`
                SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
                LEFT JOIN departments d ON dr.department_id = d.id
                LEFT JOIN companies c ON u.company_id = c.id
                WHERE dr.id = $1
            `, [req.params.id]);
            if (!rpt.rows[0]) return res.status(404).json({ success: false });
            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            const att = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
            res.json({ success: true, report: rpt.rows[0], financeItems: fd.rows, attachments: att.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/admin/reports/:id/review', apiAuth, apiAuthorize('admin_divisi', 'super_duper_admin'), async (req, res) => {
        const { status, manager_note } = req.body;
        try {
            await pool.query(`UPDATE daily_report SET status=$1, manager_note=$2 WHERE id=$3`, [status || 'approved', manager_note, req.params.id]);
            const rptRes = await pool.query(`SELECT user_id FROM daily_report WHERE id = $1`, [req.params.id]);
            if (rptRes.rows[0]) {
                await pool.query(`INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id) VALUES ($1, 'admin', $2, 'laporan_direview', $3)`,
                    [rptRes.rows[0].user_id, `Laporan #${req.params.id} telah di-review oleh ${req.session.user.full_name}.`, req.params.id]);
            }
            res.json({ success: true, message: 'Laporan berhasil di-review' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.delete('/admin/reports/:id', apiAuth, apiAuthorize('admin_divisi', 'super_admin', 'super_duper_admin'), async (req, res) => {
        try {
            const filesToDel = await getReportFiles(req.params.id, 'daily_report', pool);
            await pool.query('DELETE FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            await pool.query('DELETE FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
            await pool.query('DELETE FROM notifications WHERE reference_id=$1', [req.params.id]);
            await pool.query('DELETE FROM daily_report WHERE id=$1', [req.params.id]);
            executeDeleteFiles(filesToDel);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/admin/users', apiAuth, apiAuthorize('admin_divisi'), async (req, res) => {
        const user = req.session.user;
        try {
            const users = await pool.query(`
                SELECT u.*, r.role_name, d.department_name FROM users u
                JOIN roles r ON u.role_id = r.id LEFT JOIN departments d ON u.department_id = d.id
                WHERE u.department_id = $1 AND u.company_id = $2 ORDER BY u.full_name
            `, [user.department_id, user.company_id]);
            const roles = await pool.query(`SELECT * FROM roles ORDER BY id`);
            res.json({ success: true, users: users.rows, roles: roles.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/admin/users', apiAuth, apiAuthorize('admin_divisi'), async (req, res) => {
        const user = req.session.user;
        const { full_name, email, password, role_id, position } = req.body;
        try {
            const hash = await argon2.hash(password);
            await pool.query(`INSERT INTO users (full_name, email, password_hash, role_id, position, company_id, department_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
                [full_name, email.toLowerCase(), hash, role_id, position, user.company_id, user.department_id]);
            res.json({ success: true, message: 'User berhasil ditambahkan' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.put('/admin/users/:id', apiAuth, apiAuthorize('admin_divisi'), async (req, res) => {
        const { full_name, email, password, role_id, position, is_active } = req.body;
        try {
            if (password && password.trim()) {
                const hash = await argon2.hash(password);
                await pool.query(`UPDATE users SET full_name=$1, email=$2, password_hash=$3, role_id=$4, position=$5, is_active=$6 WHERE id=$7`,
                    [full_name, email.toLowerCase(), hash, role_id, position, is_active !== false, req.params.id]);
            } else {
                await pool.query(`UPDATE users SET full_name=$1, email=$2, role_id=$3, position=$4, is_active=$5 WHERE id=$6`,
                    [full_name, email.toLowerCase(), role_id, position, is_active !== false, req.params.id]);
            }
            res.json({ success: true, message: 'User berhasil diupdate' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ══════════════════════════════════════════════════════════════════════════
    // SUPER ADMIN
    // ══════════════════════════════════════════════════════════════════════════

    router.get('/sa/dashboard', apiAuth, apiAuthorize('super_admin', 'super_duper_admin'), async (req, res) => {
        const user = req.session.user;
        try {
            const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
            const statsRes = await pool.query(`
                SELECT dr.status, COUNT(*) as total FROM daily_report dr
                JOIN users u ON dr.user_id = u.id
                WHERE u.company_id = $1 GROUP BY dr.status
            `, [user.company_id]);
            const totalRes = await pool.query(`SELECT COUNT(*) as total FROM daily_report dr JOIN users u ON dr.user_id = u.id WHERE u.company_id = $1`, [user.company_id]);
            const todayRes = await pool.query(`SELECT COUNT(*) as total FROM daily_report dr JOIN users u ON dr.user_id = u.id WHERE u.company_id = $1 AND dr.report_date = $2`, [user.company_id, todayStr]);
            const notReported = await pool.query(`
                SELECT u.id, u.full_name, u.position, d.department_name FROM users u
                LEFT JOIN departments d ON u.department_id = d.id
                WHERE u.is_active = TRUE AND u.company_id = $1
                  AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
                  AND u.id NOT IN (SELECT user_id FROM daily_report WHERE report_date = $2)
                ORDER BY u.full_name LIMIT 10
            `, [user.company_id, todayStr]);
            const deptStats = await pool.query(`
                SELECT d.department_name, COUNT(dr.id) as report_count
                FROM departments d LEFT JOIN daily_report dr ON dr.department_id = d.id AND dr.report_date = $2
                LEFT JOIN users u ON dr.user_id = u.id AND u.company_id = $1
                WHERE d.id IN (SELECT department_id FROM company_departments WHERE company_id = $1)
                GROUP BY d.department_name ORDER BY d.department_name
            `, [user.company_id, todayStr]);
            res.json({
                success: true,
                totalReports: parseInt(totalRes.rows[0]?.total || '0'),
                todayReports: parseInt(todayRes.rows[0]?.total || '0'),
                statusStats: statsRes.rows,
                notReported: notReported.rows,
                notReportedCount: notReported.rows.length,
                deptStats: deptStats.rows,
                date: todayStr
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/sa/reports', apiAuth, apiAuthorize('super_admin', 'super_duper_admin'), async (req, res) => {
        const user = req.session.user;
        const { date_from, date_to, status, dept_id, search } = req.query;
        try {
            let sql = `
                SELECT dr.*, u.full_name, u.position, d.department_name,
                       (SELECT COALESCE(SUM(total_price), 0) FROM daily_report_finance_detail WHERE report_id = dr.id) as total_nominal
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
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
            const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);
            res.json({ success: true, reports: reports.rows, departments: depts.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/sa/activity-log', apiAuth, apiAuthorize('super_admin', 'super_duper_admin'), async (req, res) => {
        const user = req.session.user;
        try {
            const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
            const notReported = await pool.query(`
                SELECT u.full_name, c.company_name, u.position FROM users u
                JOIN companies c ON u.company_id = c.id
                WHERE u.is_active = TRUE AND u.company_id = $1
                  AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
                  AND u.id NOT IN (SELECT user_id FROM daily_report WHERE report_date = $2)
                ORDER BY u.full_name
            `, [user.company_id, todayStr]);
            res.json({ success: true, notReported: notReported.rows, date: todayStr });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/sa/employees', apiAuth, apiAuthorize('super_admin', 'super_duper_admin'), async (req, res) => {
        const user = req.session.user;
        const { dept_id, search } = req.query;
        try {
            const deptStats = await pool.query(`
                SELECT d.id, d.department_name,
                       (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.company_id = $1) as employee_count
                FROM departments d ORDER BY d.department_name ASC
            `, [user.company_id]);

            let employees = [];
            if (dept_id) {
                let empSql = `SELECT u.*, r.role_name, d.department_name FROM users u
                    JOIN roles r ON u.role_id = r.id JOIN departments d ON u.department_id = d.id
                    WHERE u.company_id = $1 AND u.department_id = $2`;
                const empParams = [user.company_id, dept_id];
                if (search) { empSql += ` AND (u.full_name ILIKE $3 OR u.email ILIKE $3)`; empParams.push(`%${search}%`); }
                empSql += ` ORDER BY u.full_name ASC`;
                const empRes = await pool.query(empSql, empParams);
                employees = empRes.rows;
            }
            res.json({ success: true, deptStats: deptStats.rows, employees });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ══════════════════════════════════════════════════════════════════════════
    // SUPER DUPER ADMIN
    // ══════════════════════════════════════════════════════════════════════════

    router.get('/sda/dashboard', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
            const totalRes = await pool.query(`SELECT COUNT(*) as total FROM daily_report`);
            const todayRes = await pool.query(`SELECT COUNT(*) as total FROM daily_report WHERE report_date = $1`, [todayStr]);
            const statusStats = await pool.query(`SELECT status, COUNT(*) as total FROM daily_report GROUP BY status`);
            const companyStats = await pool.query(`
                SELECT c.id, c.company_name, COUNT(dr.id) as report_count,
                       (SELECT COUNT(*) FROM users u2 WHERE u2.company_id = c.id AND u2.is_active = TRUE AND u2.role_id = (SELECT id FROM roles WHERE role_name = 'user')) as employee_count
                FROM companies c LEFT JOIN users u ON u.company_id = c.id
                LEFT JOIN daily_report dr ON dr.user_id = u.id AND dr.report_date = $1
                WHERE c.is_active = TRUE GROUP BY c.id, c.company_name ORDER BY c.company_name
            `, [todayStr]);
            const notReportedCount = await pool.query(`
                SELECT COUNT(*) as total FROM users u
                WHERE u.is_active = TRUE AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
                  AND u.id NOT IN (SELECT user_id FROM daily_report WHERE report_date = $1)
            `, [todayStr]);
            const totalUsers = await pool.query(`SELECT COUNT(*) as total FROM users WHERE is_active = TRUE AND role_id = (SELECT id FROM roles WHERE role_name = 'user')`);
            res.json({
                success: true,
                totalReports: parseInt(totalRes.rows[0]?.total || '0'),
                todayReports: parseInt(todayRes.rows[0]?.total || '0'),
                statusStats: statusStats.rows,
                companyStats: companyStats.rows,
                notReportedCount: parseInt(notReportedCount.rows[0]?.total || '0'),
                totalEmployees: parseInt(totalUsers.rows[0]?.total || '0'),
                date: todayStr
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/sda/reports', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { date_from, date_to, status, dept_id, company_id, search } = req.query;
        try {
            let sql = `
                SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name,
                       (SELECT COALESCE(SUM(total_price), 0) FROM daily_report_finance_detail WHERE report_id = dr.id) as total_nominal
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
                LEFT JOIN departments d ON dr.department_id = d.id LEFT JOIN companies c ON u.company_id = c.id
                WHERE 1=1
            `;
            const params = [];
            if (company_id) { sql += ` AND c.id = $${params.length + 1}`; params.push(company_id); }
            if (dept_id) { sql += ` AND dr.department_id = $${params.length + 1}`; params.push(dept_id); }
            if (status) { sql += ` AND dr.status = $${params.length + 1}`; params.push(status); }
            if (date_from) { sql += ` AND dr.report_date >= $${params.length + 1}`; params.push(date_from); }
            if (date_to) { sql += ` AND dr.report_date <= $${params.length + 1}`; params.push(date_to); }
            if (search) { sql += ` AND (u.full_name ILIKE $${params.length + 1} OR c.company_name ILIKE $${params.length + 1})`; params.push(`%${search}%`); }
            sql += ` ORDER BY dr.report_date DESC, c.company_name, d.department_name`;

            const reports = await pool.query(sql, params);
            const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
            const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);

            const statusStats = await pool.query(`SELECT status, COUNT(*) as total FROM daily_report GROUP BY status`);

            res.json({ success: true, reports: reports.rows, companies: companies.rows, departments: depts.rows, statusStats: statusStats.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.get('/sda/reports/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const rpt = await pool.query(`
                SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
                LEFT JOIN departments d ON dr.department_id = d.id LEFT JOIN companies c ON u.company_id = c.id
                WHERE dr.id = $1
            `, [req.params.id]);
            if (!rpt.rows[0]) return res.status(404).json({ success: false });
            const fd = await pool.query('SELECT * FROM daily_report_finance_detail WHERE report_id=$1', [req.params.id]);
            const att = await pool.query('SELECT * FROM daily_report_attachments WHERE report_id=$1', [req.params.id]);
            res.json({ success: true, report: rpt.rows[0], financeItems: fd.rows, attachments: att.rows });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/sda/reports/:id/review', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { status, manager_note } = req.body;
        try {
            await pool.query(`UPDATE daily_report SET status=$1, manager_note=$2 WHERE id=$3`, [status || 'approved', manager_note, req.params.id]);
            const rptRes = await pool.query(`SELECT user_id FROM daily_report WHERE id = $1`, [req.params.id]);
            if (rptRes.rows[0]) {
                await pool.query(`INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id) VALUES ($1, 'admin', $2, 'laporan_direview', $3)`,
                    [rptRes.rows[0].user_id, `Laporan #${req.params.id} telah di-review.`, req.params.id]);
            }
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    router.post('/sda/reports/:id/give-solution', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { director_solution, manager_note } = req.body;
        try {
            await pool.query(`UPDATE daily_report SET director_solution = $1, manager_note = $2 WHERE id = $3`, [director_solution, manager_note, req.params.id]);
            const rptRes = await pool.query(`SELECT user_id FROM daily_report WHERE id = $1`, [req.params.id]);
            if (rptRes.rows[0]) {
                await pool.query(`INSERT INTO notifications (recipient_user_id, sender_type, message, type, reference_id) VALUES ($1, 'admin', $2, 'laporan_direview', $3)`,
                    [rptRes.rows[0].user_id, `✅ Director telah memberikan solusi untuk laporan #${req.params.id}.`, req.params.id]);
            }
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // SDA: Companies CRUD
    router.get('/sda/companies', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const companies = await pool.query(`SELECT * FROM companies ORDER BY company_name`);
            res.json({ success: true, companies: companies.rows });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.post('/sda/companies', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { company_name, company_code, address } = req.body;
        try {
            const r = await pool.query(`INSERT INTO companies (company_name, company_code, address) VALUES ($1,$2,$3) RETURNING *`, [company_name, company_code, address]);
            res.json({ success: true, company: r.rows[0] });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.put('/sda/companies/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { company_name, company_code, address, is_active } = req.body;
        try {
            await pool.query(`UPDATE companies SET company_name=$1, company_code=$2, address=$3, is_active=$4 WHERE id=$5`,
                [company_name, company_code, address, is_active !== false, req.params.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.delete('/sda/companies/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            await pool.query('DELETE FROM companies WHERE id=$1', [req.params.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    // SDA: Departments CRUD
    router.get('/sda/departments', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const depts = await pool.query(`
                SELECT d.*, ARRAY_AGG(c.company_name) as company_names, ARRAY_AGG(c.id) as company_ids
                FROM departments d LEFT JOIN company_departments cd ON d.id = cd.department_id
                LEFT JOIN companies c ON cd.company_id = c.id GROUP BY d.id ORDER BY d.department_name
            `);
            const companies = await pool.query(`SELECT id, company_name FROM companies WHERE is_active = TRUE ORDER BY company_name`);
            res.json({
                success: true,
                departments: depts.rows.map(d => ({ ...d, company_ids: (d.company_ids || []).filter(id => id !== null), company_names: (d.company_names || []).filter(n => n !== null) })),
                companies: companies.rows
            });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.post('/sda/departments', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { department_name, company_ids } = req.body;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const r = await client.query(`INSERT INTO departments (department_name) VALUES ($1) RETURNING id`, [department_name.toUpperCase()]);
            const deptId = r.rows[0].id;
            if (company_ids && company_ids.length) {
                for (const cId of company_ids) {
                    await client.query(`INSERT INTO company_departments (company_id, department_id) VALUES ($1, $2)`, [cId, deptId]);
                }
            }
            await client.query('COMMIT');
            res.json({ success: true, departmentId: deptId });
        } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ success: false, message: err.message }); }
        finally { client.release(); }
    });

    router.put('/sda/departments/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { department_name, company_ids } = req.body;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(`UPDATE departments SET department_name=$1 WHERE id=$2`, [department_name.toUpperCase(), req.params.id]);
            await client.query(`DELETE FROM company_departments WHERE department_id = $1`, [req.params.id]);
            if (company_ids && company_ids.length) {
                for (const cId of company_ids) {
                    await client.query(`INSERT INTO company_departments (company_id, department_id) VALUES ($1, $2)`, [cId, req.params.id]);
                }
            }
            await client.query('COMMIT');
            res.json({ success: true });
        } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ success: false, message: err.message }); }
        finally { client.release(); }
    });

    router.delete('/sda/departments/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            await pool.query('DELETE FROM departments WHERE id=$1', [req.params.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    // SDA: Users CRUD
    router.get('/sda/users', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { company_id, dept_id, search } = req.query;
        try {
            let sql = `SELECT u.*, r.role_name, c.company_name, d.department_name FROM users u
                JOIN roles r ON u.role_id = r.id LEFT JOIN companies c ON u.company_id = c.id
                LEFT JOIN departments d ON u.department_id = d.id WHERE 1=1`;
            const params = [];
            if (company_id) { sql += ` AND u.company_id = $${params.length + 1}`; params.push(company_id); }
            if (dept_id) { sql += ` AND u.department_id = $${params.length + 1}`; params.push(dept_id); }
            if (search) { sql += ` AND (u.full_name ILIKE $${params.length + 1} OR u.email ILIKE $${params.length + 1})`; params.push(`%${search}%`); }
            sql += ` ORDER BY c.company_name, d.department_name, u.full_name`;

            const users = await pool.query(sql, params);
            const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
            const depts = await pool.query(`SELECT * FROM departments ORDER BY department_name`);
            const roles = await pool.query(`SELECT * FROM roles ORDER BY id`);
            res.json({ success: true, users: users.rows, companies: companies.rows, departments: depts.rows, roles: roles.rows });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.post('/sda/users', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { full_name, email, password, role_id, position, company_id, department_id } = req.body;
        try {
            const hash = await argon2.hash(password);
            const r = await pool.query(`INSERT INTO users (full_name, email, password_hash, role_id, position, company_id, department_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
                [full_name, email.toLowerCase(), hash, role_id, position, company_id || null, department_id || null]);
            res.json({ success: true, userId: r.rows[0].id });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.put('/sda/users/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { full_name, email, password, role_id, position, company_id, department_id, is_active } = req.body;
        try {
            if (password && password.trim()) {
                const hash = await argon2.hash(password);
                await pool.query(`UPDATE users SET full_name=$1, email=$2, password_hash=$3, role_id=$4, position=$5, company_id=$6, department_id=$7, is_active=$8 WHERE id=$9`,
                    [full_name, email.toLowerCase(), hash, role_id, position, company_id || null, department_id || null, is_active !== false, req.params.id]);
            } else {
                await pool.query(`UPDATE users SET full_name=$1, email=$2, role_id=$3, position=$4, company_id=$5, department_id=$6, is_active=$7 WHERE id=$8`,
                    [full_name, email.toLowerCase(), role_id, position, company_id || null, department_id || null, is_active !== false, req.params.id]);
            }
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.delete('/sda/users/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const userId = req.params.id;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query('DELETE FROM audit_logs WHERE user_id = $1', [userId]);
            await client.query('DELETE FROM notifications WHERE recipient_user_id = $1', [userId]);
            const reportsRes = await client.query('SELECT id FROM daily_report WHERE user_id = $1', [userId]);
            let filesToDel = [];
            for (const r of reportsRes.rows) {
                await client.query('DELETE FROM notifications WHERE reference_id = $1', [r.id]);
                await client.query('DELETE FROM daily_report_attachments WHERE report_id = $1', [r.id]);
                await client.query('DELETE FROM daily_report_finance_detail WHERE report_id = $1', [r.id]);
                filesToDel.push(...(await getReportFiles(r.id, 'daily_report', client)));
            }
            await client.query('DELETE FROM daily_eport WHERE user_id = $1', [userId]);
            executeDeleteFiles(filesToDel);
            await client.query('DELETE FROM users WHERE id = $1', [userId]);
            await client.query('COMMIT');
            res.json({ success: true });
        } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ success: false, message: err.message }); }
        finally { client.release(); }
    });

    // SDA: Periods CRUD
    router.get('/sda/periods', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const periods = await pool.query(`SELECT rp.*, c.company_name FROM report_periods rp LEFT JOIN companies c ON rp.company_id=c.id ORDER BY rp.start_date DESC`);
            const companies = await pool.query(`SELECT * FROM companies WHERE is_active=TRUE ORDER BY company_name`);
            res.json({ success: true, periods: periods.rows, companies: companies.rows });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.post('/sda/periods', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { period_name, company_id, start_date, end_date, deadline } = req.body;
        try {
            const r = await pool.query(`INSERT INTO report_periods (period_name, company_id, start_date, end_date, deadline) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
                [period_name, company_id || null, start_date, end_date, deadline || null]);
            res.json({ success: true, periodId: r.rows[0].id });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.put('/sda/periods/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { period_name, company_id, start_date, end_date, deadline, is_active } = req.body;
        try {
            await pool.query(`UPDATE report_periods SET period_name=$1, company_id=$2, start_date=$3, end_date=$4, deadline=$5, is_active=$6 WHERE id=$7`,
                [period_name, company_id || null, start_date, end_date, deadline || null, is_active !== false, req.params.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    router.delete('/sda/periods/:id', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            await pool.query('DELETE FROM report_periods WHERE id=$1', [req.params.id]);
            res.json({ success: true });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    // SDA: Activity Log
    router.get('/sda/activity-log', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta' }).format(new Date());
            const notReported = await pool.query(`
                SELECT u.full_name, c.company_name, u.position FROM users u
                JOIN companies c ON u.company_id = c.id
                WHERE u.is_active = TRUE AND u.role_id = (SELECT id FROM roles WHERE role_name = 'user')
                  AND u.id NOT IN (SELECT user_id FROM daily_report WHERE report_date = $1)
                ORDER BY c.company_name, u.full_name
            `, [todayStr]);
            res.json({ success: true, notReported: notReported.rows, date: todayStr });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    // SDA: Urgent
    router.get('/sda/urgent', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        try {
            const urgentReports = await pool.query(`
                SELECT dr.*, u.full_name, u.position, d.department_name, c.company_name,
                       CASE WHEN (dr.director_solution IS NOT NULL AND dr.director_solution != '') THEN TRUE ELSE FALSE END as is_solved
                FROM daily_report dr JOIN users u ON dr.user_id = u.id
                LEFT JOIN departments d ON dr.department_id = d.id LEFT JOIN companies c ON u.company_id = c.id
                WHERE dr.is_asked_director = TRUE
                ORDER BY CASE WHEN (dr.director_solution IS NULL OR dr.director_solution = '') THEN 0 ELSE 1 END ASC, dr.created_at DESC
            `);
            res.json({ success: true, urgentReports: urgentReports.rows });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    // SDA: Employees (multi-company)
    router.get('/sda/employees', apiAuth, apiAuthorize('super_duper_admin'), async (req, res) => {
        const { company_id, dept_id, search } = req.query;
        try {
            if (!company_id) {
                const companies = await pool.query(`SELECT c.*, (SELECT COUNT(*) FROM users u WHERE u.company_id = c.id) as employee_count FROM companies c WHERE is_active = TRUE ORDER BY company_name`);
                return res.json({ success: true, viewMode: 'company_list', companies: companies.rows });
            }
            const deptStats = await pool.query(`SELECT d.id, d.department_name, (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.company_id = $1) as employee_count FROM departments d ORDER BY d.department_name ASC`, [company_id]);
            let employees = [];
            if (dept_id) {
                let empSql = `SELECT u.*, r.role_name, d.department_name FROM users u JOIN roles r ON u.role_id = r.id JOIN departments d ON u.department_id = d.id WHERE u.company_id = $1 AND u.department_id = $2`;
                const empParams = [company_id, dept_id];
                if (search) { empSql += ` AND (u.full_name ILIKE $3 OR u.email ILIKE $3)`; empParams.push(`%${search}%`); }
                empSql += ` ORDER BY u.full_name ASC`;
                employees = (await pool.query(empSql, empParams)).rows;
            }
            res.json({ success: true, viewMode: 'employee_data', deptStats: deptStats.rows, employees });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    return router;
};
