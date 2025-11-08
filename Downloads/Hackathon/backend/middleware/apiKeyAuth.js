import { db } from '../config/firebase-admin.js';

/**
 * Middleware to verify API key
 * Extracts API key from Authorization header or X-API-Key header and verifies it
 */
export const verifyApiKey = async (req, res, next) => {
  try {
    // Get API key from Authorization header (Bearer token) or X-API-Key header
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'];
    
    let apiKey = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      apiKey = authHeader.split('Bearer ')[1];
    } else if (apiKeyHeader) {
      apiKey = apiKeyHeader;
    }
    
    if (!apiKey) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'API key is required. Provide it in Authorization header (Bearer <key>) or X-API-Key header' 
      });
    }

    // Verify API key exists in Firestore
    const apiRef = db.collection('api');
    const snapshot = await apiRef.where('apiKey', '==', apiKey).where('isActive', '==', true).get();

    if (snapshot.empty) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid or inactive API key' 
      });
    }

    // Get the API key document
    const apiDoc = snapshot.docs[0];
    const apiData = apiDoc.data();

    // Attach API key info to request object
    req.apiKey = {
      key: apiKey,
      appId: apiData.appId,
      userId: apiData.userId,
      apiKeyId: apiDoc.id
    };

    next();
  } catch (error) {
    console.error('API key verification error:', error);
    return res.status(401).json({ 
      error: 'Unauthorized', 
      message: 'Failed to verify API key' 
    });
  }
};
