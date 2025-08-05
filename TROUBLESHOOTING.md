# Deployment Troubleshooting Guide

## 🚨 500 Internal Server Error

If you're getting a 500 error, follow these steps:

### 1. Check the Debug Endpoint
Visit `/debug` on your deployed app to see what's wrong:
```
https://your-app.railway.app/debug
```

### 2. Check the Health Endpoint
Visit `/health` to see basic status:
```
https://your-app.railway.app/health
```

### 3. Common Issues and Solutions

#### Database Connection Issues
**Symptoms**: Database errors in logs
**Solution**: 
- Ensure `DATABASE_URL` environment variable is set
- For Railway: Check if PostgreSQL is provisioned
- For Render: Add PostgreSQL service

#### Missing Environment Variables
**Symptoms**: Secret key errors
**Solution**:
- Set `SECRET_KEY` environment variable
- Set `FLASK_ENV=production`

#### Import Errors
**Symptoms**: Module not found errors
**Solution**:
- Check `requirements.txt` includes all dependencies
- Ensure all Python files are in the repository

### 4. Platform-Specific Debugging

#### Railway
1. Go to your project dashboard
2. Click on "Deployments" tab
3. Check the build logs for errors
4. Check the function logs for runtime errors

#### Render
1. Go to your service dashboard
2. Click on "Logs" tab
3. Look for error messages in the logs

#### Heroku
```bash
heroku logs --tail
```

### 5. Quick Fixes

#### Reset Database
If database issues persist:
```python
# Add this temporarily to app.py
@app.route('/reset-db')
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return jsonify({'message': 'Database reset'})
```

#### Force Database Initialization
```python
# Add this to ensure_db_initialized()
print(f"Database URL: {get_database_url()}")
print(f"Current working directory: {os.getcwd()}")
```

### 6. Test Locally First
Run the test script before deploying:
```bash
python3 test_deployment.py
```

### 7. Environment Variables Checklist
- [ ] `SECRET_KEY` - Random secret key
- [ ] `DATABASE_URL` - PostgreSQL connection string
- [ ] `FLASK_ENV` - Set to `production`

### 8. Common Error Messages

#### "No module named 'psycopg2'"
- Add `psycopg2-binary` to requirements.txt

#### "Database is locked"
- SQLite issue on serverless platforms
- Switch to PostgreSQL

#### "Secret key not set"
- Set `SECRET_KEY` environment variable

#### "Template not found"
- Ensure `templates/` folder is included in deployment

### 9. Emergency Debug Mode
Add this to temporarily get more info:
```python
@app.route('/emergency-debug')
def emergency_debug():
    return jsonify({
        'environment_vars': dict(os.environ),
        'app_config': dict(app.config),
        'working_dir': os.getcwd(),
        'files': os.listdir('.')
    })
```

### 10. Still Having Issues?
1. Check the platform's documentation
2. Look at the build logs
3. Try a different platform (Railway → Render → Heroku)
4. Consider using Docker for consistent environments 