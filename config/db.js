const mongoose = require('mongoose');

const connectDB = async () => {
  try {
  
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }

    // Connect to MongoDB
    mongoose.set('strictQuery', true);

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    // Only show detailed logs in development
    if (process.env.NODE_ENV === 'development') {
      console.log('');
      console.log('='.repeat(50));
      console.log(`✅ MongoDB Connected`);
      console.log(`📊 Host: ${conn.connection.host}`);
      console.log(`🗄️  Database: ${conn.connection.name}`);
      console.log('='.repeat(50));
      console.log('');
    } else {
      // Production: Simple success message
      console.log('✅ MongoDB Connected');
    }

    // Connection event handlers - Only in development
    if (process.env.NODE_ENV === 'development') {
      mongoose.connection.on('connected', () => {
        console.log('✅ Mongoose connected to DB');
      });

      mongoose.connection.on('error', (err) => {
        console.error('❌ Mongoose connection error:', err);
      });

      mongoose.connection.on('disconnected', () => {
        console.warn('⚠️  Mongoose disconnected from DB');
      });
    } else {
      // Production: Only log critical errors
      mongoose.connection.on('error', (err) => {
        console.error('MongoDB connection error');
      });
    }

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      if (process.env.NODE_ENV === 'development') {
        console.log('🔌 MongoDB connection closed through app termination');
      }
      process.exit(0);
    });

  } catch (error) {
    // Error handling - Different for dev and production
    if (process.env.NODE_ENV === 'development') {
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
        
        
      }

      console.error('='.repeat(50));
      console.error('');
    } else {
      // Production: Simple error message without details
      console.error('❌ MongoDB connection failed');
      console.error('Check environment variables and database configuration');
    }
    
    process.exit(1);
  }
};

module.exports = connectDB;