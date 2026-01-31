# CyberShare Scanner - Backend Setup

## 🚀 Quick Start

### 1. Install Backend Dependencies
```bash
# Navigate to your project directory
cd c:\Users\user\Desktop\vite-cybershare

# Install backend dependencies
npm install --save express node-fetch cors express-rate-limit

# Or use the separate package file
cp package-server.json package-server-lock.json
npm install --prefix . --production
```

### 2. Start the Backend Server
```bash
# Start the scanner API server
node server.js
```

The backend will start on `http://localhost:3001`

### 3. Start the Frontend
```bash
# In a new terminal, start the Vite frontend
npm run dev
```

The frontend will start on `http://localhost:3000`

## 🛡️ Scanner Features

### Security Checks Performed:
1. **Security Headers Analysis**
   - Content Security Policy (CSP)
   - Strict Transport Security (HSTS)
   - X-Frame-Options
   - X-Content-Type-Options
   - Referrer-Policy
   - X-XSS-Protection
   - Permissions-Policy

2. **SSL/TLS Verification**
   - HTTPS detection
   - Certificate validation
   - TLS recommendations

3. **Port Detection**
   - Common web ports (80, 443, 8080, 8443)
   - Open port identification
   - Security recommendations

4. **Technology Fingerprinting**
   - Server headers
   - Framework detection
   - Library identification

## 🔧 API Endpoints

### Main Scanner Endpoint
```
POST http://localhost:3001/api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Health Check
```
GET http://localhost:3001/api/health
```

## 📝 Usage Example

1. Open your browser to `http://localhost:3000`
2. Navigate to the Scanner page
3. Enter a website URL (must be your own website)
4. Check the acknowledgment box
5. Click "Initiate Deep Scan"
6. View real-time results in the sidebar

## ⚠️ Important Notes

- **Rate Limiting**: 10 scans per 15 minutes per IP
- **Timeout**: 10 seconds per scan request
- **Legal**: Only scan websites you own or have permission to test
- **CORS**: Backend proxy bypasses browser CORS restrictions

## 🚀 Deployment

### For Production:
1. Deploy backend to a server (Heroku, Vercel, AWS)
2. Update frontend API URL from `localhost:3001` to your backend URL
3. Configure environment variables for security
4. Set up proper rate limiting and monitoring

### Environment Variables:
```bash
PORT=3001
NODE_ENV=production
```

## 🔒 Security Features

- Rate limiting to prevent abuse
- Request timeout protection
- URL validation
- Error handling and logging
- CORS enabled for frontend integration

## 📊 Response Format

```json
{
  "success": true,
  "url": "https://example.com",
  "timestamp": "2024-01-30T04:55:00.000Z",
  "results": [
    {
      "title": "SECURITY HEADERS",
      "status": "FAIL",
      "recommendation": "Missing headers: content-security-policy, strict-transport-security",
      "details": {
        "present": ["x-frame-options"],
        "missing": ["content-security-policy", "strict-transport-security"],
        "totalHeaders": 12
      }
    }
  ]
}
```

## 🐛 Troubleshooting

### Backend won't start:
- Check if port 3001 is available
- Verify Node.js is installed
- Check dependencies are installed

### Frontend can't connect:
- Ensure backend is running on port 3001
- Check for CORS errors in browser console
- Verify API URL in scanner.html

### Scans failing:
- Check target website is accessible
- Verify URL format (include https://)
- Check network connectivity
