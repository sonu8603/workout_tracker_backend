// debugLogin.js - Complete login debugging
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

async function debugLogin() {
  try {
    console.log('🔍 Starting Login Debug...\n');

    // 1. Check environment
    console.log('📋 Environment Check:');
    console.log('   MONGODB_URI:', process.env.MONGODB_URI ? '✅ Set' : '❌ Missing');
    console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '✅ Set' : '❌ Missing');
    console.log('');

    // 2. Connect to database
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected!\n');

    const User = require('./models/User');

    // 3. List all users
    console.log('👥 Users in database:');
    const users = await User.find({}).select('+password');
    
    if (users.length === 0) {
      console.log('❌ No users found! Register a user first.\n');
      process.exit(1);
    }

    users.forEach((user, index) => {
      console.log(`\n   ${index + 1}. User:`);
      console.log(`      Email: ${user.email}`);
      console.log(`      Username: ${user.username}`);
      console.log(`      Phone: ${user.phone}`);
      console.log(`      Active: ${user.isActive}`);
      console.log(`      Password Hash: ${user.password?.substring(0, 20)}...`);
      console.log(`      Hash Valid: ${user.password?.startsWith('$2') ? '✅ YES' : '❌ NO (not hashed!)'}`);
    });

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TESTING LOGIN FOR FIRST USER');
    console.log('='.repeat(60));

    const testUser = users[0];
    console.log(`\n📧 Testing: ${testUser.email}`);

    // 4. Test common passwords
    const commonPasswords = [
      '123456',
      'password',
      'test123',
      'Test123',
      'Test@123',
      'admin123',
      'qwerty',
      '12345678'
    ];

    console.log('\n🔑 Testing common passwords:');
    let foundPassword = null;

    for (const pwd of commonPasswords) {
      try {
        const isMatch = await bcrypt.compare(pwd, testUser.password);
        if (isMatch) {
          console.log(`   ✅ "${pwd}" - MATCH FOUND!`);
          foundPassword = pwd;
          break;
        } else {
          console.log(`   ❌ "${pwd}" - no match`);
        }
      } catch (error) {
        console.log(`   ⚠️  "${pwd}" - error: ${error.message}`);
      }
    }

    if (!foundPassword) {
      console.log('\n⚠️  None of the common passwords matched.');
      console.log('💡 The password might be custom. Try entering it manually.\n');
    }

    // 5. Check if password is hashed
    console.log('\n🔐 Password Analysis:');
    if (!testUser.password.startsWith('$2')) {
      console.log('❌ PASSWORD IS NOT HASHED!');
      console.log('   This means the pre-save hook in User model is not working.');
      console.log('   Password stored as plain text:', testUser.password);
      console.log('\n💡 Fix: The password should be hashed during registration.');
      
      // Try to match plain text
      if (testUser.password === '123456' || testUser.password === 'test123') {
        console.log(`\n✅ Plain text password is: "${testUser.password}"`);
        foundPassword = testUser.password;
      }
    } else {
      console.log('✅ Password is properly hashed (bcrypt)');
      console.log(`   Algorithm: ${testUser.password.substring(0, 4)}`);
      console.log(`   Salt rounds: ~12`);
    }

    // 6. Test complete login flow
    if (foundPassword) {
      console.log('\n' + '='.repeat(60));
      console.log('🚀 TESTING COMPLETE LOGIN FLOW');
      console.log('='.repeat(60));

      // Test with email
      console.log(`\n1️⃣  Testing login with EMAIL: ${testUser.email}`);
      const userByEmail = await User.findOne({ 
        email: testUser.email.toLowerCase() 
      }).select('+password');
      
      if (userByEmail) {
        const emailMatch = await userByEmail.comparePassword(foundPassword);
        console.log(`   Result: ${emailMatch ? '✅ SUCCESS' : '❌ FAILED'}`);
      }

      // Test with username
      console.log(`\n2️⃣  Testing login with USERNAME: ${testUser.username}`);
      const userByUsername = await User.findOne({ 
        username: testUser.username 
      }).select('+password');
      
      if (userByUsername) {
        const usernameMatch = await userByUsername.comparePassword(foundPassword);
        console.log(`   Result: ${usernameMatch ? '✅ SUCCESS' : '❌ FAILED'}`);
      }

      // Test JWT generation
      console.log('\n3️⃣  Testing JWT token generation...');
      try {
        const token = jwt.sign(
          { id: testUser._id },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );
        console.log('   ✅ Token generated successfully');
        console.log(`   Token: ${token.substring(0, 30)}...`);

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('   ✅ Token verified successfully');
        console.log(`   User ID: ${decoded.id}`);
      } catch (error) {
        console.log(`   ❌ Token error: ${error.message}`);
      }

      // 7. Provide working credentials
      console.log('\n' + '='.repeat(60));
      console.log('✅ WORKING LOGIN CREDENTIALS');
      console.log('='.repeat(60));
      console.log(`\nEmail:    ${testUser.email}`);
      console.log(`Username: ${testUser.username}`);
      console.log(`Password: ${foundPassword}`);
      console.log('\n💡 Use these credentials in your Flutter app!');
    }

    // 8. Test API endpoint format
    console.log('\n' + '='.repeat(60));
    console.log('🌐 CURL COMMAND TO TEST');
    console.log('='.repeat(60));
    console.log('\nRun this command in terminal:\n');
    console.log(`curl -X POST http://localhost:5000/api/auth/login \\`);
    console.log(`  -H "Content-Type: application/json" \\`);
    console.log(`  -d '{"identifier":"${testUser.email}","password":"${foundPassword || 'YOUR_PASSWORD"}'}\n`);

    mongoose.connection.close();
    console.log('\n✅ Debug complete!\n');

  } catch (error) {
    console.error('\n❌ Error during debug:', error);
    process.exit(1);
  }
}

debugLogin();