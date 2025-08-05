# Admin Guide - Private Messenger

## 🚀 Quick Start

### 1. Set Up Admin User
Run the admin setup script to create your first admin user:
```bash
python3 create_admin.py
```

### 2. Access Admin Dashboard
- Log in with your admin credentials
- Visit `/admin` to access the admin dashboard
- Navigate through different admin sections

## 🔧 Admin Features

### User Management
- **View all users** with pagination and search
- **Edit user details** (role, permissions, status)
- **Activate/deactivate users**
- **Manage user roles** (user, moderator, admin, super_admin)
- **View user activity** (last seen, login attempts)

### Message Management
- **Review all messages** in the system
- **Flag inappropriate messages**
- **Delete messages** (soft delete)
- **Filter flagged messages**
- **View message details** (sender, receiver, timestamp)

### System Logs
- **Security logs** - Login attempts, user actions
- **Admin action logs** - All admin activities
- **Audit trail** - Complete system activity history

### System Settings
- **Configure system parameters**
- **Manage rate limits**
- **Enable/disable features**
- **Maintenance mode**

## 👥 User Roles & Permissions

### User Roles
1. **user** - Regular user with basic permissions
2. **moderator** - Can flag messages and manage basic content
3. **admin** - Full admin access to users and messages
4. **super_admin** - Complete system control

### Permission System
- **Granular permissions** via JSON string
- **Role-based access control**
- **Custom permission assignments**

## 🛡️ Security Features

### Account Protection
- **Login attempt tracking**
- **Automatic account lockout**
- **Session validation**
- **IP address logging**

### Content Moderation
- **Message flagging system**
- **Content filtering**
- **Admin review workflow**
- **Audit logging**

## 📊 Admin Dashboard Sections

### Dashboard Overview
- **System statistics** (users, messages, activity)
- **Recent user registrations**
- **Recent message activity**
- **Real-time updates**

### User Management
- **User listing** with search and filters
- **User editing** with role management
- **Account status** control
- **User activity** monitoring

### Message Management
- **Message review** interface
- **Content moderation** tools
- **Flagged message** handling
- **Message deletion** (soft delete)

### System Logs
- **Security event** logging
- **Admin action** tracking
- **User activity** monitoring
- **System audit** trail

### Settings
- **System configuration**
- **Feature toggles**
- **Rate limiting** settings
- **Maintenance mode**

## 🔍 API Endpoints

### User Management
- `GET /api/admin/users` - List all users
- `GET /api/admin/user/<id>` - Get user details
- `PUT /api/admin/user/<id>` - Update user
- `DELETE /api/admin/user/<id>` - Deactivate user

### Message Management
- `GET /api/admin/messages` - List messages
- `PUT /api/admin/message/<id>` - Update message
- `DELETE /api/admin/message/<id>` - Delete message

### System Information
- `GET /api/admin/stats` - System statistics
- `GET /api/admin/logs` - System logs

## 🚨 Emergency Actions

### Account Lockout
If a user account is compromised:
1. Go to User Management
2. Find the user
3. Click "Deactivate"
4. Review security logs

### Content Removal
For inappropriate content:
1. Go to Message Management
2. Find the message
3. Click "Flag" or "Delete"
4. Review flagged messages

### System Maintenance
To enable maintenance mode:
1. Go to Settings
2. Set "maintenance_mode" to true
3. Users will see maintenance page

## 📈 Monitoring & Analytics

### Key Metrics
- **User growth** - New registrations
- **Activity levels** - Messages sent
- **Security events** - Failed logins, flags
- **System health** - Database performance

### Alerts
- **High failed login** attempts
- **Multiple flagged** messages
- **System errors** or warnings
- **Unusual activity** patterns

## 🔐 Security Best Practices

### Admin Account Security
- **Use strong passwords**
- **Enable 2FA** if available
- **Regular password** changes
- **Monitor admin** login attempts

### System Security
- **Regular log** reviews
- **Monitor user** activity
- **Review flagged** content
- **Update system** settings

### Data Protection
- **Audit trail** maintenance
- **Secure data** handling
- **Privacy compliance**
- **Backup procedures**

## 🛠️ Troubleshooting

### Common Issues

#### Can't Access Admin Dashboard
- Check if user has admin privileges
- Verify user is active
- Check session validity

#### User Management Not Working
- Verify database connection
- Check user permissions
- Review error logs

#### Message Moderation Issues
- Check message permissions
- Verify flagging system
- Review content filters

### Debug Tools
- **Health check** endpoint: `/health`
- **Debug info** endpoint: `/debug`
- **Emergency debug** endpoint: `/emergency-debug`

## 📞 Support

### Getting Help
1. Check the troubleshooting section
2. Review system logs
3. Test with debug endpoints
4. Contact system administrator

### Emergency Contacts
- **System Admin** - For critical issues
- **Security Team** - For security incidents
- **Technical Support** - For technical problems

---

## 🎯 Quick Reference

### Admin URLs
- Dashboard: `/admin`
- Users: `/admin/users`
- Messages: `/admin/messages`
- Logs: `/admin/logs`
- Settings: `/admin/settings`

### Key Commands
```bash
# Create admin user
python3 create_admin.py

# Run the application
python3 app.py

# Test deployment
python3 test_deployment.py
```

### Default Settings
- Max login attempts: 5
- Lockout duration: 15 minutes
- Message length limit: 1000 characters
- Rate limit: 20 requests per hour
- Registration: Enabled
- Maintenance mode: Disabled 