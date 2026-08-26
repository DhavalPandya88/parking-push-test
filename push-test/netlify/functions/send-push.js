const webPush = require('web-push');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ ok: false, error: 'Method not allowed' }) };
  }

  try {
    const { subscription, title, body, url } = JSON.parse(event.body);

    if (!subscription || !subscription.endpoint) {
      return { statusCode: 400, body: JSON.stringify({ ok: false, error: 'Missing subscription' }) };
    }

    const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
    const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;

    if (!vapidPublicKey || !vapidPrivateKey) {
      return { statusCode: 500, body: JSON.stringify({ ok: false, error: 'VAPID keys not configured on the server' }) };
    }

    webPush.setVapidDetails(
      'mailto:admin@example.com',
      vapidPublicKey,
      vapidPrivateKey
    );

    const payload = JSON.stringify({
      title: title || 'Notification',
      body: body || '',
      url: url || '/'
    });

    await webPush.sendNotification(subscription, payload);

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        ok: false,
        error: err.message,
        statusCode: err.statusCode || null,
        details: err.body || null
      })
    };
  }
};
