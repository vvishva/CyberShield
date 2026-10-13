/**
 * CyberShield — Network Risk Controller
 *
 * RESTful endpoints for SOC dashboard events, metrics summary,
 * investigation details, triage actions, manual IP checks, and admin config.
 */

const NetworkRiskEvent = require('../models/NetworkRiskEvent');
const NetworkRiskConfig = require('../models/NetworkRiskConfig');
const Log = require('../models/Log');
const { inspectIp, extractClientIp } = require('../services/anonymousNetworkService');
const { getRiskSummary, getConfig } = require('../services/networkRiskService');

// @desc    Get summary statistics for SOC dashboard metric cards
// @route   GET /api/network-risk/summary
// @access  Private
exports.getSummary = async (req, res, next) => {
  try {
    const summary = await getRiskSummary();
    res.status(200).json({
      success: true,
      data: summary
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get paginated, filtered, and sorted risk events
// @route   GET /api/network-risk/events
// @access  Private
exports.getEvents = async (req, res, next) => {
  try {
    const {
      riskLevel,
      networkType,
      status,
      search,
      startDate,
      endDate,
      sort = 'newest',
      page = 1,
      limit = 20
    } = req.query;

    const query = {};

    // RBAC: If standard user (non-admin), restrict to their own events or anonymous
    if (req.user && req.user.role !== 'admin') {
      query.$or = [{ userId: req.user._id }, { userId: null }];
    }

    // Filter: Risk Level
    if (riskLevel && riskLevel !== 'all') {
      query.riskLevel = { $regex: new RegExp(`^${riskLevel.trim()}$`, 'i') };
    }

    // Filter: Network Type
    if (networkType && networkType !== 'all') {
      query.networkType = { $regex: new RegExp(`^${networkType.trim()}$`, 'i') };
    }

    // Filter: Status
    if (status && status !== 'all') {
      query.status = { $regex: new RegExp(`^${status.trim()}$`, 'i') };
    }

    // Filter: Free-text search (IP address or Username)
    if (search && search.trim()) {
      const cleanSearch = search.trim();
      query.$or = [
        { ipAddress: { $regex: cleanSearch, $options: 'i' } },
        { username: { $regex: cleanSearch, $options: 'i' } },
        { country: { $regex: cleanSearch, $options: 'i' } }
      ];
    }

    // Filter: Date Range
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    // Sorting
    let sortObj = { createdAt: -1 };
    switch (sort) {
      case 'oldest':
        sortObj = { createdAt: 1 };
        break;
      case 'risk_desc':
        sortObj = { riskScore: -1, createdAt: -1 };
        break;
      case 'risk_asc':
        sortObj = { riskScore: 1, createdAt: -1 };
        break;
      case 'signals_desc':
        sortObj = { 'signals.length': -1, createdAt: -1 };
        break;
      case 'newest':
      default:
        sortObj = { createdAt: -1 };
    }

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
    const skip = (pageNum - 1) * limitNum;

    const [events, total] = await Promise.all([
      NetworkRiskEvent.find(query)
        .sort(sortObj)
        .skip(skip)
        .limit(limitNum)
        .lean(),
      NetworkRiskEvent.countDocuments(query)
    ]);

    res.status(200).json({
      success: true,
      count: events.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum) || 1,
      data: events
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get detailed event by ID for Investigation modal
// @route   GET /api/network-risk/events/:id
// @access  Private
exports.getEventById = async (req, res, next) => {
  try {
    const event = await NetworkRiskEvent.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Network risk event not found.' });
    }

    // Audit Log: Analyst viewed investigation details
    try {
      if (req.user) {
        await Log.create({
          user: req.user._id,
          username: req.user.username,
          action: 'NETWORK_RISK_VIEWED',
          details: `Analyst opened investigation on event ${event._id} (${event.ipAddress})`,
          status: 'SUCCESS'
        });
      }
    } catch (_) {}

    res.status(200).json({
      success: true,
      data: event
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Mark a risk event as Reviewed / Triaged
// @route   PATCH /api/network-risk/events/:id/review
// @access  Private
exports.markReviewed = async (req, res, next) => {
  try {
    const event = await NetworkRiskEvent.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Network risk event not found.' });
    }

    const reviewerName = req.user ? req.user.username : 'Security Analyst';

    event.status = 'Reviewed';
    event.reviewed = true;
    event.reviewedBy = reviewerName;
    event.reviewedAt = new Date();
    await event.save();

    // Audit Log
    try {
      if (req.user) {
        await Log.create({
          user: req.user._id,
          username: req.user.username,
          action: 'NETWORK_RISK_REVIEWED',
          details: `Analyst reviewed risk event ${event._id} (${event.ipAddress} - ${event.riskLevel})`,
          status: 'SUCCESS'
        });
      }
    } catch (_) {}

    res.status(200).json({
      success: true,
      message: 'Event marked as reviewed.',
      data: event
    });
  } catch (err) {
    next(err);
  }
};

// @desc    On-demand manual IP inspection tool for analysts
// @route   POST /api/network-risk/check-ip
// @access  Private
exports.manualCheckIp = async (req, res, next) => {
  try {
    const { ip } = req.body;
    const targetIp = ip && ip.trim() ? ip.trim() : extractClientIp(req);

    const intel = await inspectIp(targetIp);
    res.status(200).json({
      success: true,
      data: intel
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get active risk scoring configuration (Admin only)
// @route   GET /api/network-risk/config
// @access  Private/Admin
exports.getConfigSettings = async (req, res, next) => {
  try {
    const config = await getConfig();
    res.status(200).json({
      success: true,
      data: config
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update risk scoring configuration (Admin only)
// @route   PUT /api/network-risk/config
// @access  Private/Admin
exports.updateConfigSettings = async (req, res, next) => {
  try {
    const {
      enabled,
      weights,
      thresholds,
      alertThreshold,
      cacheDurationHours,
      cooldownMinutes,
      provider
    } = req.body;

    let config = await NetworkRiskConfig.findOne({ configKey: 'default_config' });
    if (!config) {
      config = new NetworkRiskConfig({ configKey: 'default_config' });
    }

    if (typeof enabled === 'boolean') config.enabled = enabled;
    if (weights && typeof weights === 'object') {
      config.weights = { ...config.weights, ...weights };
    }
    if (thresholds && typeof thresholds === 'object') {
      config.thresholds = { ...config.thresholds, ...thresholds };
    }
    if (alertThreshold) config.alertThreshold = alertThreshold;
    if (cacheDurationHours) config.cacheDurationHours = Math.max(1, parseInt(cacheDurationHours, 10));
    if (cooldownMinutes) config.cooldownMinutes = Math.max(1, parseInt(cooldownMinutes, 10));
    if (provider) config.provider = provider;
    config.updatedBy = req.user ? req.user.username : 'Admin';

    await config.save();

    // Audit Log
    try {
      if (req.user) {
        await Log.create({
          user: req.user._id,
          username: req.user.username,
          action: 'NETWORK_RISK_CONFIG_UPDATED',
          details: `Admin updated Anonymous Network Risk Detection configuration`,
          status: 'SUCCESS'
        });
      }
    } catch (_) {}

    res.status(200).json({
      success: true,
      message: 'Risk detection configuration updated successfully.',
      data: config
    });
  } catch (err) {
    next(err);
  }
};
