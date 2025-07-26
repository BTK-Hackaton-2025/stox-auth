# NestJS gRPC Authentication Microservice

A production-ready, layered architecture authentication microservice built with NestJS, gRPC, PostgreSQL, and Passport JWT authentication.

## 🏗️ Architecture Overview

This microservice follows a **layered architecture** pattern:

```
├── src/
│   ├── presentation/           # Presentation Layer
│   │   ├── auth/              # gRPC Controllers, Guards, Strategies, DTOs
│   │   └── health/            # HTTP Health Check Controllers
│   ├── business-logic/        # Business Logic Layer
│   │   └── services/          # Authentication, JWT, Password services
│   ├── infrastructure/        # Infrastructure Layer
│   │   └── database/          # Entities, Repositories, Configuration
│   ├── config/                # Configuration & Validation
│   └── proto/                 # Protocol Buffer definitions
```

### Key Features

- ✅ **gRPC with Protocol Buffers** for high-performance communication
- ✅ **JWT Token Authentication** with refresh tokens and proper gRPC validation
- ✅ **bcrypt Password Hashing** for secure password storage
- ✅ **PostgreSQL** with TypeORM for data persistence
- ✅ **Passport.js** strategies (JWT & Local)
- ✅ **Role-based Authorization** (RBAC)
- ✅ **Rate Limiting** with endpoint-specific throttling
- ✅ **Input Validation** with DTOs and custom validation pipes
- ✅ **Layered Architecture** with clean separation of concerns
- ✅ **Token Management** with refresh token rotation
- ✅ **Secure Error Handling** with sanitized responses
- ✅ **Environment Validation** with startup configuration checks
- ✅ **Type Safety** throughout the application

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- PostgreSQL 13+
- Protocol Buffers compiler (`protoc`) - for generating TypeScript types from .proto files

**Installing protoc:**
```bash
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt install protobuf-compiler

# Windows (using chocolatey)
choco install protoc

# Or download from: https://github.com/protocolbuffers/protobuf/releases
```

### Installation

1. **Clone and install dependencies:**
```bash
npm install
```

2. **Set up environment variables:**
```bash
cp env.example .env
# Edit .env with your configuration
# Ensure JWT secrets are at least 32 characters (required for startup)
```

3. **Generate secure JWT secrets:**
```bash
# Generate secure 32+ character secrets
openssl rand -base64 32  # Use for JWT_ACCESS_SECRET
openssl rand -base64 32  # Use for JWT_REFRESH_SECRET
```

4. **Generate TypeScript types from protobuf (optional):**
```bash
npm run proto:generate
# This generates TypeScript interfaces from src/proto/auth.proto
# Only needed if you modify the .proto file
```

5. **Start the application:**
```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

The gRPC server will start on `localhost:50051` and HTTP health check server on `localhost:3000`.

## 📋 API Reference

### HTTP Health Check Endpoints

The HTTP server provides health check endpoints for monitoring:

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /` | Service info | Service details and available endpoints |
| `GET /health` | General health check | Status, uptime, timestamp |
| `GET /health/ready` | Readiness probe | Kubernetes-compatible readiness check |
| `GET /health/live` | Liveness probe | Kubernetes-compatible liveness check |

**Example:**
```bash
curl http://localhost:3000/health
# Returns: {"status":"ok","timestamp":"2024-01-01T12:00:00.000Z","service":"stox-auth-microservice","version":"1.0.0","uptime":123.45}
```

### gRPC Service Methods

#### Authentication Methods

**Register User**
```protobuf
rpc Register(RegisterRequest) returns (AuthResponse);
```

**Login User**
```protobuf
rpc Login(LoginRequest) returns (AuthResponse);
```

**Validate Token**
```protobuf
rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
```

**Refresh Tokens**
```protobuf
rpc RefreshToken(RefreshTokenRequest) returns (AuthResponse);
```

**Logout User**
```protobuf
rpc Logout(LogoutRequest) returns (LogoutResponse);
```

#### Profile Management

**Get User Profile**
```protobuf
rpc GetProfile(GetProfileRequest) returns (UserProfileResponse);
```

**Update Profile**
```protobuf
rpc UpdateProfile(UpdateProfileRequest) returns (UserProfileResponse);
```

**Change Password**
```protobuf
rpc ChangePassword(ChangePasswordRequest) returns (OperationResponse);
```

### Rate Limiting & Validation

All endpoints are protected with rate limiting and input validation:

| Endpoint | Rate Limit | Validation |
|----------|------------|------------|
| `Register` | 1 req/min | Email format, password complexity, name length |
| `Login` | 5 req/min | Email format, password required |
| `ValidateToken` | Unlimited | Token format |
| `RefreshToken` | 10 req/min | Token format |
| `Logout` | 10 req/min | Optional token validation |
| `GetProfile` | 30 req/min | User authorization |
| `UpdateProfile` | 10 req/min | Email format, name length, authorization |
| `ChangePassword` | 3 req/min | Password complexity, authorization |

### Example Usage

#### Node.js gRPC Client

```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

// Load proto definition
const packageDefinition = protoLoader.loadSync('auth.proto');
const authProto = grpc.loadPackageDefinition(packageDefinition).auth;

// Create client
const client = new authProto.AuthService('localhost:50051', 
  grpc.credentials.createInsecure());

// Register user
client.Register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  firstName: 'John',
  lastName: 'Doe',
  role: 'user'
}, (error, response) => {
  if (error) {
    console.error('Error:', error);
  } else {
    console.log('Registration successful:', response);
  }
});

// Login user
client.Login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
}, (error, response) => {
  if (error) {
    console.error('Error:', error);
  } else {
    console.log('Login successful:', response);
    const { accessToken, refreshToken } = response.tokenData;
    // Store tokens securely
  }
});
```

## 🔒 Security Features

### Password Security
- **bcrypt** hashing algorithm with configurable salt rounds
- **Complex password requirements** (uppercase, lowercase, numbers, special chars)
- **Automatic password strength validation** with detailed error messages
- **Password rehashing detection** for security upgrades

### Token Security
- **JWT Access Tokens** (short-lived, 15 minutes) with proper gRPC validation
- **Refresh Tokens** (long-lived, 7 days) stored in database with metadata
- **Automatic token rotation** on refresh for enhanced security
- **Token revocation support** with reason tracking
- **Secure token storage** with IP address and user agent tracking

### Rate Limiting & DDoS Protection
- **Endpoint-specific throttling** with different limits per operation
- **Registration**: 1 req/min (strict anti-spam)
- **Login**: 5 req/min (brute force protection)
- **Password changes**: 3 req/min (strict security)
- **Token validation**: Unlimited (performance optimization)

### Input Validation & Sanitization
- **DTO-based validation** with class-validator decorators
- **Custom gRPC validation pipe** for microservice requests
- **Automatic data transformation** and sanitization
- **Email normalization** (lowercase, trimming)
- **Input length restrictions** and format validation

### Error Handling & Information Security
- **Global exception filter** prevents information leakage
- **Sanitized error responses** for client-facing errors
- **Detailed server-side logging** for debugging
- **No internal error exposure** to prevent attack vectors

### Configuration Security
- **Environment validation** at startup with clear error messages
- **Required JWT secrets** (minimum 32 characters)
- **Type-safe configuration** with proper defaults
- **Secure development practices** with comprehensive .env.example

### Authorization
- **Role-based access control** (RBAC) with enum validation
- **Route-level authorization** with JWT and roles guards
- **Method-level permissions** with custom decorators
- **User context injection** for secure request handling

## 🏗️ Architecture Details

### Layered Architecture

#### 1. Presentation Layer (`src/presentation/`)
- **Auth Controllers**: Handle gRPC requests and responses with validation
- **Health Controllers**: HTTP endpoints for health checks and monitoring
- **DTOs**: Data Transfer Objects with validation decorators
- **Guards**: Authentication and authorization guards (JWT + Roles)
- **Strategies**: Passport authentication strategies (JWT + Local)
- **Decorators**: Custom decorators for authentication and authorization
- **Filters**: Global exception filter for secure error handling
- **Pipes**: Custom validation pipes for gRPC requests

#### 2. Business Logic Layer (`src/business-logic/`)
- **AuthService**: Core authentication business logic
- **JwtTokenService**: JWT token generation and validation
- **PasswordService**: Password hashing and validation

#### 3. Infrastructure Layer (`src/infrastructure/`)
- **Entities**: TypeORM database entities
- **Repositories**: Data access layer with repository pattern
- **Configuration**: Database and application configuration

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    is_email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Refresh Tokens Table
```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT false,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 Configuration

### Environment Variables

**Required Configuration** (validated at startup):

```bash
# Environment
NODE_ENV=development

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=your_secure_password_here
DB_NAME=stox_auth
DB_MAX_CONNECTIONS=10
DB_MIN_CONNECTIONS=1

# JWT Configuration (REQUIRED - Must be at least 32 characters)
# Generate secure secrets: openssl rand -base64 32
JWT_ACCESS_SECRET=your_super_secure_access_secret_here_at_least_32_chars
JWT_REFRESH_SECRET=your_super_secure_refresh_secret_here_at_least_32_chars
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Server Configuration
GRPC_HOST=0.0.0.0
GRPC_PORT=50051
HTTP_PORT=3000
```

**Optional Configuration** (for future features):

```bash
# Email Configuration (for email verification - future feature)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
FROM_EMAIL=noreply@yourapp.com
```

⚠️ **Security Notes:**
- JWT secrets must be at least 32 characters long (enforced)
- Application will fail to start with invalid configuration
- Use `openssl rand -base64 32` to generate secure secrets
- Never commit actual secrets to version control

## 🧪 Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## 📦 Deployment

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 50051 3000

CMD ["npm", "run", "start:prod"]
```

### Production Considerations

1. **Environment Security**:
   - Use strong, unique JWT secrets (32+ characters, enforced)
   - Enable SSL for database connections
   - Set `NODE_ENV=production`
   - Use secret management services (AWS Secrets Manager, etc.)

2. **Database**:
   - Disable `synchronize` in TypeORM (automatically disabled in production)
   - Run migrations manually
   - Set up connection pooling
   - Enable SSL connections

3. **Security Hardening**:
   - Review and adjust rate limiting for your use case
   - Monitor for brute force attacks
   - Set up intrusion detection
   - Regular security audits

4. **Monitoring & Logging**:
   - Implement health checks (HTTP endpoint on port 3000)
   - Add structured logging and metrics
   - Set up alerting for authentication failures
   - Monitor token validation patterns

5. **Performance**:
   - Tune JWT token expiration times
   - Monitor database connection pool usage
   - Consider Redis for rate limiting storage
   - Load testing for concurrent users

## 🤝 Usage with API Gateway

This auth microservice is designed to work behind an API Gateway:

```
Client → API Gateway (REST) → Auth Microservice (gRPC)
```

Example API Gateway integration:
- **Public endpoints**: `/api/auth/login`, `/api/auth/register`
- **Protected endpoints**: `/api/auth/profile`, `/api/auth/refresh`
- **Token validation**: Gateway calls `ValidateToken` for protected routes

## 📚 Additional Resources

- [NestJS Documentation](https://docs.nestjs.com/)
- [gRPC Node.js Guide](https://grpc.io/docs/languages/node/)
- [Protocol Buffers Guide](https://developers.google.com/protocol-buffers)
- [TypeORM Documentation](https://typeorm.io/)
- [Passport.js Documentation](http://www.passportjs.org/)

## 🔄 API Gateway Integration

For a complete setup with REST API Gateway, consider implementing:

1. **REST-to-gRPC Translation Layer**
2. **Rate Limiting and CORS**
3. **Request/Response Transformation**
4. **Load Balancing**
5. **Circuit Breaker Pattern**

This microservice provides the authentication foundation for a scalable microservices architecture. 