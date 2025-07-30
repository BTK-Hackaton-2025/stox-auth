const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

// Load the proto file
const packageDefinition = protoLoader.loadSync('./src/proto/auth.proto', {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const authProto = grpc.loadPackageDefinition(packageDefinition).auth;

// Create gRPC client
const client = new authProto.AuthService(
  'localhost:50051',
  grpc.credentials.createInsecure()
);

// Test registration data
const testData = {
  email: 'test@example.com',
  password: 'TestPass132!', // Meets all requirements
  firstName: 'Test',
  lastName: 'User',
  role: 'user'
};

console.log('🚀 Testing registration with data:', {
  email: testData.email,
  password: '***', // Don't log actual password
  firstName: testData.firstName,
  lastName: testData.lastName,
  role: testData.role
});

// Make the registration call
client.Register(testData, (error, response) => {
  if (error) {
    console.error('❌ Registration failed:', error.message);
    if (error.details) {
      console.error('Validation errors:', error.details);
    }
  } else {
    console.log('✅ Registration successful!');
    console.log('Response:', {
      success: response.success,
      message: response.message,
      userId: response.userData?.id,
      email: response.userData?.email,
      hasTokens: !!response.tokenData
    });
  }
}); 