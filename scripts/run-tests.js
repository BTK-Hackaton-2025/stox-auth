#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

console.log('🧪 Starting gRPC Auth Service Tests...\n');

// Check if auth service is running
function checkServiceHealth() {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();
    
    socket.setTimeout(5000);
    
    socket.on('connect', () => {
      console.log('✅ Auth service is running on port 50051');
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', () => {
      console.log('❌ Auth service is not running on port 50051');
      console.log('💡 Please start the auth service first: npm run start:dev');
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', () => {
      console.log('❌ Auth service is not running on port 50051');
      console.log('💡 Please start the auth service first: npm run start:dev');
      socket.destroy();
      resolve(false);
    });
    
    socket.connect(50051, 'localhost');
  });
}

// Run Jest tests
function runTests() {
  return new Promise((resolve, reject) => {
    const jestProcess = spawn('npx', ['jest', 'test/test-registration.test.js', '--verbose', '--detectOpenHandles'], {
      stdio: 'inherit',
      shell: true
    });
    
    jestProcess.on('close', (code) => {
      if (code === 0) {
        console.log('\n✅ All tests passed!');
        resolve();
      } else {
        console.log(`\n❌ Tests failed with code ${code}`);
        reject(new Error(`Tests failed with code ${code}`));
      }
    });
    
    jestProcess.on('error', (error) => {
      console.error('❌ Failed to run tests:', error.message);
      reject(error);
    });
  });
}

// Main execution
async function main() {
  try {
    const serviceRunning = await checkServiceHealth();
    
    if (!serviceRunning) {
      process.exit(1);
    }
    
    console.log('\n🚀 Running registration tests...\n');
    await runTests();
    
  } catch (error) {
    console.error('💥 Test execution failed:', error.message);
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Tests interrupted by user');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Tests terminated');
  process.exit(0);
});

// Run the tests
main(); 