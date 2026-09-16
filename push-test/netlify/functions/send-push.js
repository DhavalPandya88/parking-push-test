const { sendWebPush } = require('./webpush-lite');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ ok: false, error: 'Method not allowed' }) };
  }

  try {
    const { subscription, title, body, url } = JSON.parse(event.body);

    if (!subscription || !subscription.endpoint || !subscription.keys) {
      return { statusCode: 400, body: JSON.stringify({ ok: false, error: 'Missing or invalid subscription' }) };
    }

    const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
    const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;

    if (!vapidPublicKey || !vapidPrivateKey) {
      return { statusCode: 500, body: JSON.stringify({ ok: false, error: 'VAPID keys not configured on the server' }) };
    }

    await sendWebPush(
      subscription,
      { title: title || 'Notification', body: body || '', url: url || '/' },
      vapidPublicKey,
      vapidPrivateKey,
      'mailto:admin@example.com'
    );

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ ok: false, error: err.message }) };
  }
};
