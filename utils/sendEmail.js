const nodemailer = require("nodemailer");

const sendEmail = async (options) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST, 
      port: Number(process.env.EMAIL_PORT), 
      secure: false, 
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        rejectUnauthorized: false, 
      },
    });

    await transporter.verify();
    console.log("SMTP READY");

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: options.email,
      subject: options.subject,
      html: options.html,
    });

    console.log(" Email sent to:", options.email);
    return true;
  } catch (error) {
    console.error(" Email send error:", error);
    return false;
  }
};

module.exports = sendEmail;