/**
 * middleware/auth.js
 * Middleware untuk proteksi route berdasarkan session dan role
 */

// Pastikan user sudah login
const isAuth = (req, res, next) => {
    const isJson = req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1);

    if (req.session && req.session.user) {
        if (req.session.user.isDirector) {
            if (isJson) return res.status(401).json({ success: false, message: 'Invalid role for this route' });
            return res.redirect('/director/dashboard');
        }
        return next();
    }
    // Jika sedang dalam proses MFA
    if (req.session && req.session.tempUser) {
        if (isJson) return res.status(401).json({ success: true, mfa_required: true });
        return res.redirect('/verify-mfa');
    }

    if (isJson) {
        return res.status(401).json({ success: false, message: 'Sesi habis. Silakan login kembali.' });
    }
    res.redirect('/login');
};

// Role-based access control
const authorize = (...roles) => {
    return (req, res, next) => {
        const isJson = req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1);
        if (!req.session || !req.session.user) {
            if (isJson) return res.status(401).json({ success: false, message: 'Unauthorized' });
            return res.redirect('/login');
        }
        const userRole = req.session.user.role_name;
        console.log("****************==",req.session.user);
        console.log("****************==","NEEDS :", roles);
        if (roles.includes(userRole)) {
            return next();
        }
        // Log akses ditolak untuk debugging
        console.warn('[AUTH DENIED]', {
            path: req.path,
            method: req.method,
            userId: req.session.user.id,
            userRole,
            requiredRoles: roles,
            reason: `User role "${userRole}" not in allowed roles [${roles.join(', ')}]`
        });
        if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
            return res.status(403).json({ success: false, message: 'Akses Ditolak' });
        }
        return res.status(403).render('500', {
            user: req.session.user,
            error: 'Akses Ditolak: Anda tidak memiliki izin untuk halaman ini.'
        });
    };
};

// Mencatat audit log
const auditLog = (pool) => async (req, res, next) => {
    // Bisa digunakan sebagai middleware di route tertentu
    req.writeAudit = async (action, targetTable, targetId, oldValue, newValue) => {
        try {
            const userId = req.session?.user?.id || null;
            const ip = req.ip || req.connection?.remoteAddress || null;
            await pool.query(`
                INSERT INTO audit_logs (user_id, action, target_table, target_id, old_value, new_value, ip_address)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            `, [userId, action, targetTable, targetId,
                oldValue ? JSON.stringify(oldValue) : null,
                newValue ? JSON.stringify(newValue) : null,
                ip]);
        } catch (e) {
            console.error('Audit log error:', e.message);
        }
    };
    next();
};

const isDirectorAuth = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.isDirector) {
        return next();
    }
    if (req.session && req.session.tempUser && req.session.tempUser.isDirector) {
        return res.redirect('/verify-mfa');
    }
    res.redirect('/director/login');
};

const authorizeDirector = (...roles) => {
    return (req, res, next) => {
        if (!req.session || !req.session.user || !req.session.user.isDirector) {
            return res.redirect('/director/login');
        }
        const userRole = req.session.user.role_name;
        if (roles.includes(userRole)) {
            return next();
        }
        // Log akses ditolak untuk debugging
        console.warn('[AUTH DENIED - DIRECTOR]', {
            path: req.path,
            method: req.method,
            userId: req.session.user.id,
            userRole,
            requiredRoles: roles,
            reason: `Director role "${userRole}" not in allowed roles [${roles.join(', ')}]`
        });
        return res.status(403).render('500', {
            user: req.session.user,
            error: 'Akses Ditolak: Anda tidak memiliki izin untuk halaman ini.'
        });
    };
};

const isAnyAuth = (req, res, next) => {
    if (req.session && req.session.user) return next();
    res.redirect('/login');
};

module.exports = { isAuth, authorize, auditLog, isDirectorAuth, authorizeDirector, isAnyAuth };
