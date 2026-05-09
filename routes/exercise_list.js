const express = require('express');
const mongoose = require('mongoose');

const router = express.Router();

const Exercise = require('../models/exercises_model');

/**
 * ==================================================
 * SEARCH EXERCISES
 * ==================================================
 * GET /api/exercises/search?q=bench
 */

router.get('/search', async (req, res, next) => {
  try {
    const q = req.query.q;

    if (!q) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required',
      });
    }

    const exercises = await Exercise.find({
      name: {
        $regex: q,
        $options: 'i',
      },
    })
      .select('-__v')
      .limit(20)
      .lean();

    return res.status(200).json({
      success: true,
      count: exercises.length,
      data: exercises,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * ==================================================
 * GET CARDIO EXERCISES
 * ==================================================
 * GET /api/exercises/category/cardio
 */

router.get('/category/cardio', async (req, res, next) => {
  try {
    const exercises = await Exercise.find({
      bodyPartId: 'cardio',
    })
      .select('-__v')
      .sort({ name: 1 })
      .lean();

    return res.status(200).json({
      success: true,
      count: exercises.length,
      data: exercises,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * ==================================================
 * GET EXERCISES BY BODY PART
 * ==================================================
 * GET /api/exercises/bodypart/chest
 */

router.get('/bodypart/:bodyPartId', async (req, res, next) => {
  try {
    const exercises = await Exercise.find({
      bodyPartId: req.params.bodyPartId.toLowerCase(),
    })
      .select('-__v')
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      success: true,
      count: exercises.length,
      data: exercises,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * ==================================================
 * GET SINGLE EXERCISE
 * ==================================================
 * GET /api/exercises/:id
 */

router.get('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid exercise ID',
      });
    }

    const exercise = await Exercise.findById(id).select('-__v').lean();

    if (!exercise) {
      return res.status(404).json({
        success: false,
        message: 'Exercise not found',
      });
    }

    return res.status(200).json({
      success: true,
      data: exercise,
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
