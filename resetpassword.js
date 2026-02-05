// resetPassword.js - Reset a user's password to a known value
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

async function resetPassword() {
  try {
    console.log('🔐 Password Reset Tool\n');

    // Connect to database
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB\n');

    const User = require('./models/User');

    // Configuration - CHANGE THESE VALUES
   const userEmail = 'surajkushwaha.9730@gmail.com';  // ← Apna email
const newPassword = 'suraj@9730';                // New password to set

    console.log('📋 Reset Configuration:');
    console.log(`   Email: ${userEmail}`);
    console.log(`   New Password: ${newPassword}`);
    console.log('');

    // Find user
    const user = await User.findOne({ email: userEmail });

    if (!user) {
      console.log('❌ User not found with email:', userEmail);
      console.log('💡 Make sure the email is correct\n');
      process.exit(1);
    }

    console.log('✅ User found!');
    console.log(`   Username: ${user.username}`);
    console.log(`   Email: ${user.email}\n`);

    // Set new password (the pre-save hook will hash it)
    console.log('🔄 Setting new password...');
    user.password = newPassword;  // Set as plain text, hook will hash it
    user.passwordChangedAt = Date.now() - 1000;
    await user.save();  // This will trigger the pre-save hook to hash it
    console.log('✅ Password saved\n');

    console.log('✅ Password updated successfully!\n');

    // Verify the new password works
    console.log('🧪 Verifying new password...');
    const userCheck = await User.findOne({ email: userEmail }).select('+password');
    const isMatch = await bcrypt.compare(newPassword, userCheck.password);

    if (isMatch) {
      console.log('✅ Password verification: SUCCESS!\n');
      
      console.log('='.repeat(60));
      console.log('✅ PASSWORD RESET COMPLETE');
      console.log('='.repeat(60));
      console.log('\n🎉 You can now login with:');
      console.log(`   Email:    ${userEmail}`);
      console.log(`   Username: ${user.username}`);
      console.log(`   Password: ${newPassword}`);
      console.log('\n💡 Use these credentials in your Flutter app!\n');

      // Provide curl command
      console.log('🌐 Test with cURL:');
      console.log(`\ncurl -X POST http://localhost:3000/api/auth/login \\`);
      console.log(`  -H "Content-Type: application/json" \\`);
      console.log(`  -d '{"identifier":"${userEmail}","password":"${newPassword}"}'\n`);
    } else {
      console.log('❌ Password verification: FAILED');
      console.log('⚠️  Something went wrong. Please try again.\n');
    }

    mongoose.connection.close();
    process.exit(0);

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error(error);
    process.exit(1);
  }
}

resetPassword();