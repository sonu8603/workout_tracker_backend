const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  try {
    console.log('📧 Attempting to send email to:', options.email);

    // 🔥 UPDATED: Better config for Render
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: false, // Use STARTTLS
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      // 🔥 NEW: Connection settings for cloud environments
      connectionTimeout: 10000,  // 10 seconds
      greetingTimeout: 10000,    // 10 seconds
      socketTimeout: 60000,      // 60 seconds
      pool: true,                // Use connection pooling
      maxConnections: 5,         // Max 5 connections
      // 🔥 NEW: TLS settings
      tls: {
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2'
      },
      // 🔥 NEW: Debug logging
      logger: process.env.NODE_ENV === 'development',
      debug: process.env.NODE_ENV === 'development'
    });

    const mailOptions = {
      from: `"FitMetrics" <${process.env.EMAIL_FROM}>`,
      to: options.email,
      subject: options.subject,
      html: options.message,
    };

    console.log('📧 Sending email...');
    const info = await transporter.sendMail(mailOptions);
    
    console.log(' Email sent successfully!');
    console.log('   Message ID:', info.messageId);
    console.log('   Response:', info.response);
    
    return info;

  } catch (error) {
    console.error('❌ Email send error:', error);
    console.error('   Code:', error.code);
    console.error('   Command:', error.command);
    throw new Error(`Email failed: ${error.message}`);
  }
};

module.exports = sendEmail;