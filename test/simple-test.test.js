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

describe('Simple gRPC Test', () => {
  let client;

  beforeAll(() => {
    client = new authProto.AuthService(
      'localhost:50051',
      grpc.credentials.createInsecure()
    );
  });

  afterAll(() => {
    if (client) {
      client.close();
    }
  });

  test('should connect to gRPC service', async () => {
    const testData = {
      email: `simple-test-${Date.now()}@example.com`,
      password: 'TestPass132!',
      firstName: 'Simple',
      lastName: 'Test',
      role: 'user'
    };

    console.log('🧪 Running simple test...');

    return new Promise((resolve, reject) => {
      client.Register(testData, (error, response) => {
        if (error) {
          console.log('❌ Test failed:', error.message);
          reject(error);
          return;
        }

        console.log('✅ Test passed!');
        console.log('Response:', {
          success: response.success,
          message: response.message,
          hasTokens: !!response.tokenData
        });

        expect(response.success).toBe(true);
        resolve();
      });
    });
  });
}); 