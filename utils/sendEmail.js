const { Resend } = require('resend');

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);


const sendEmail = async (options) => {
  try {
    console.log('📧 Attempting to send email to:', options.email);

    // Verify API key
    if (!process.env.RESEND_API_KEY) {
      throw new Error('RESEND_API_KEY not configured');
    }


    const data = await resend.emails.send({
      from: 'FitMetrics <noreply@resend.dev>',
      to: options.email,
      subject: options.subject,
      html: options.html,  
    });

    console.log('✅ Email sent successfully!');
    console.log('Email ID:', data?.data?.id);

    console.log('   Sent to:', options.email);
    
    return {
      success: true,
      messageId: response.data.id
    };

  } catch (error) {
    console.error('❌ Email send error:', error.message);
    throw new Error(`Email failed: ${error.message}`);
  }
};

module.exports = sendEmail;