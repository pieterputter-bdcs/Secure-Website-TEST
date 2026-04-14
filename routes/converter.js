'use strict';

const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const CM_PER_INCH = 2.54;

// POST /api/convert
router.post('/', requireAuth, (req, res) => {
  const { value, from } = req.body;

  if (value === undefined || value === null || !from) {
    return res.status(400).json({ error: 'value and from are required' });
  }

  const num = parseFloat(value);
  if (!Number.isFinite(num)) {
    return res.status(400).json({ error: 'value must be a valid number' });
  }
  if (num < 0) {
    return res.status(400).json({ error: 'value must be non-negative' });
  }

  let result, fromUnit, toUnit;

  if (from === 'cm') {
    result = num / CM_PER_INCH;
    fromUnit = 'cm';
    toUnit = 'in';
  } else if (from === 'in') {
    result = num * CM_PER_INCH;
    fromUnit = 'in';
    toUnit = 'cm';
  } else {
    return res.status(400).json({ error: 'from must be "cm" or "in"' });
  }

  res.json({
    input: num,
    fromUnit,
    result: parseFloat(result.toFixed(6)),
    toUnit,
    formula: from === 'cm'
      ? `${num} cm ÷ 2.54 = ${result.toFixed(4)} in`
      : `${num} in × 2.54 = ${result.toFixed(4)} cm`,
  });
});

module.exports = router;
