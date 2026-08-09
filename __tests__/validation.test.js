const { register, login, scanUrl, scanWebsite, scanPassword, scanIp, updateProfile, createTip, generateReport } = require('../middleware/validation');

describe('Validation Middleware', () => {
  const mockReq = (body = {}) => ({ body, params: {}, query: {} });
  const mockRes = () => {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    return res;
  };
  const mockNext = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('register validator', () => {
    test('passes valid registration', () => {
      const req = mockReq({ username: 'testuser', email: 'test@example.com', password: 'Str0ng!Pass' });
      register[0](req, mockRes(), mockNext); // First middleware (body validators)
      register[1](req, mockRes(), mockNext); // handleValidationErrors
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails short username', () => {
      const req = mockReq({ username: 'ab', email: 'test@example.com', password: 'Str0ng!Pass' });
      register[0](req, mockRes(), mockNext);
      register[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, error: 'Validation failed' })
      );
    });

    test('fails invalid email', () => {
      const req = mockReq({ username: 'testuser', email: 'invalid', password: 'Str0ng!Pass' });
      register[0](req, mockRes(), mockNext);
      register[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    test('fails weak password', () => {
      const req = mockReq({ username: 'testuser', email: 'test@example.com', password: 'weak' });
      register[0](req, mockRes(), mockNext);
      register[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('login validator', () => {
    test('passes valid login', () => {
      const req = mockReq({ email: 'test@example.com', password: 'anypassword' });
      login[0](req, mockRes(), mockNext);
      login[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails missing email', () => {
      const req = mockReq({ password: 'anypassword' });
      login[0](req, mockRes(), mockNext);
      login[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('scanUrl validator', () => {
    test('passes valid URL', () => {
      const req = mockReq({ url: 'https://example.com' });
      scanUrl[0](req, mockRes(), mockNext);
      scanUrl[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails invalid URL', () => {
      const req = mockReq({ url: 'not-a-url' });
      scanUrl[0](req, mockRes(), mockNext);
      scanUrl[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('scanWebsite validator', () => {
    test('passes valid URL', () => {
      const req = mockReq({ url: 'https://example.com' });
      scanWebsite[0](req, mockRes(), mockNext);
      scanWebsite[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('scanPassword validator', () => {
    test('passes password', () => {
      const req = mockReq({ password: 'anypassword' });
      scanPassword[0](req, mockRes(), mockNext);
      scanPassword[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('scanIp validator', () => {
    test('passes valid IPv4', () => {
      const req = mockReq({ ip: '8.8.8.8' });
      scanIp[0](req, mockRes(), mockNext);
      scanIp[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('passes valid IPv6', () => {
      const req = mockReq({ ip: '2001:4860:4860::8888' });
      scanIp[0](req, mockRes(), mockNext);
      scanIp[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails invalid IP', () => {
      const req = mockReq({ ip: 'not-an-ip' });
      scanIp[0](req, mockRes(), mockNext);
      scanIp[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('updateProfile validator', () => {
    test('passes valid profile', () => {
      const req = mockReq({ username: 'newuser', avatar: 'avatar.png', twoFactorEnabled: true, emailNotifications: false });
      updateProfile[0](req, mockRes(), mockNext);
      updateProfile[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails short username', () => {
      const req = mockReq({ username: 'ab' });
      updateProfile[0](req, mockRes(), mockNext);
      updateProfile[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('createTip validator', () => {
    test('passes valid tip', () => {
      const req = mockReq({ title: 'Security Tip', category: 'Password Safety', content: 'Use strong passwords always', severity: 'INFO' });
      createTip[0](req, mockRes(), mockNext);
      createTip[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails short title', () => {
      const req = mockReq({ title: 'Tip', category: 'Password Safety', content: 'Use strong passwords always' });
      createTip[0](req, mockRes(), mockNext);
      createTip[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    test('fails invalid category', () => {
      const req = mockReq({ title: 'Security Tip', category: 'Invalid Category', content: 'Use strong passwords always' });
      createTip[0](req, mockRes(), mockNext);
      createTip[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('generateReport validator', () => {
    test('passes valid report', () => {
      const req = mockReq({ 
        title: 'Audit Report', 
        target: 'https://example.com', 
        scanType: 'url_phishing', 
        riskScore: 50,
        findings: [],
        recommendations: []
      });
      generateReport[0](req, mockRes(), mockNext);
      generateReport[1](req, mockRes(), mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('fails invalid scanType', () => {
      const req = mockReq({ 
        title: 'Audit Report', 
        target: 'https://example.com', 
        scanType: 'invalid_type', 
        riskScore: 50
      });
      generateReport[0](req, mockRes(), mockNext);
      generateReport[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    test('fails invalid riskScore', () => {
      const req = mockReq({ 
        title: 'Audit Report', 
        target: 'https://example.com', 
        scanType: 'url_phishing', 
        riskScore: 150
      });
      generateReport[0](req, mockRes(), mockNext);
      generateReport[1](req, mockRes(), mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });
});