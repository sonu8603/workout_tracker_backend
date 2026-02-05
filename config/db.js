// config/db.js
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Validate MongoDB URI
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }

    // Connect to MongoDB
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('');
    console.log('='.repeat(50));
    console.log(`✅ MongoDB Connected`);
    console.log(`📊 Host: ${conn.connection.host}`);
    console.log(`🗄️  Database: ${conn.connection.name}`);
    console.log('='.repeat(50));
    console.log('');

    // Connection event handlers
    mongoose.connection.on('connected', () => {
      console.log('✅ Mongoose connected to DB');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌ Mongoose connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️ Mongoose disconnected from DB');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🔌 MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (error) {
    console.error('');
    console.error('='.repeat(50));
    console.error('❌ MongoDB Connection Error');
    console.error('='.repeat(50));
    console.error(`Error: ${error.message}`);
    
    if (error.message.includes('ECONNREFUSED')) {
      console.error('');
      console.error('💡 Troubleshooting:');
      console.error('   1. Is MongoDB running?');
      console.error('   2. Check if MONGODB_URI is correct in .env');
      console.error('   3. For local MongoDB: run `mongod` in terminal');
      console.error('   4. For MongoDB Atlas: check network access settings');
    }
    
    if (error.message.includes('MONGODB_URI is not defined')) {
      console.error('');
      console.error('💡 Configuration issue:');
      console.error('   1. Create a .env file in root directory');
      console.error('   2. Add: MONGODB_URI=mongodb://localhost:27017/workout-tracker');
      console.error('   3. Restart the server');
    }

    console.error('='.repeat(50));
    console.error('');
    
    process.exit(1);
  }
};

module.exports = connectDB;