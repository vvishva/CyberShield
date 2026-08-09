const jwt = require('jsonwebtoken');
const { protect, authorize } = require('../middleware/authMiddleware');

describe('Auth Middleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      headers: {},
      cookies: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
    
    process.env.JWT_SECRET = 'test_secret_key_for_testing_only_32chars!!';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('protect', () => {
    test('returns 401 when no token provided', async () => {
      await protect(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, error: 'Not authorized to access this route. Token missing.' })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('returns 401 for invalid token', async () => {
      mockReq.headers.authorization = 'Bearer invalid.token.here';
      await protect(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, error: 'Not authorized. Invalid or expired token.' })
      );
    });

    test('returns 401 when JWT_SECRET not set', async () => {
      delete process.env.JWT_SECRET;
      const token = jwt.sign({ id: '123', role: 'user' }, 'some-secret');
      mockReq.headers.authorization = `Bearer ${token}`;
      await protect(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    test('calls next() with valid token (using fallback)', async () => {
      const token = jwt.sign({ id: '123', username: 'testuser', email: 'test@example.com', role: 'user' }, process.env.JWT_SECRET);
      mockReq.headers.authorization = `Bearer ${token}`;
      await protect(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
      expect(mockReq.user.id).toBe('123');
      expect(mockReq.user.username).toBe('testuser');
    });
  });

  describe('authorize', () => {
    test('allows admin role', () => {
      mockReq.user = { role: 'admin' };
      const middleware = authorize('admin');
      middleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('allows user role when authorized', () => {
      mockReq.user = { role: 'user' };
      const middleware = authorize('user');
      middleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('denies user when admin required', () => {
      mockReq.user = { role: 'user' };
      const middleware = authorize('admin');
      middleware(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, error: 'Forbidden. Insufficient permissions.' })
      );
    });

    test('denies when no user', () => {
      mockReq.user = null;
      const middleware = authorize('admin');
      middleware(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(403);
    });
  });
});