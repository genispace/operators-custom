/**
 * Lightweight performance helpers (object pool, debounce, throttle, LRU).
 */

class ObjectPool {
  constructor(createFn, resetFn, initialSize = 10) {
    this.createFn = createFn;
    this.resetFn = resetFn;
    this.pool = [];

    for (let i = 0; i < initialSize; i++) {
      this.pool.push(this.createFn());
    }
  }

  acquire() {
    return this.pool.length > 0 ? this.pool.pop() : this.createFn();
  }

  release(obj) {
    if (this.resetFn) {
      this.resetFn(obj);
    }
    this.pool.push(obj);
  }

  size() {
    return this.pool.length;
  }
}

// Reuse plain objects shaped like API responses to cut allocations on hot paths
const responsePool = new ObjectPool(
  () => ({ success: true, data: null, timestamp: null }),
  (obj) => {
    obj.success = true;
    obj.data = null;
    obj.timestamp = null;
    delete obj.message;
    delete obj.error;
    delete obj.code;
    delete obj.metadata;
  },
  50
);

function createFastResponse(success, data, extra = {}) {
  const response = responsePool.acquire();
  response.success = success;
  response.data = data;
  response.timestamp = new Date().toISOString();

  Object.assign(response, extra);

  return response;
}

function releaseFastResponse(response) {
  responsePool.release(response);
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function throttle(func, limit) {
  let inThrottle;
  return function executedFunction(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

class LRUCache {
  constructor(maxSize = 100) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (this.cache.has(key)) {
      const value = this.cache.get(key);
      this.cache.delete(key);
      this.cache.set(key, value);
      return value;
    }
    return undefined;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  has(key) {
    return this.cache.has(key);
  }

  clear() {
    this.cache.clear();
  }

  size() {
    return this.cache.size;
  }
}

module.exports = {
  ObjectPool,
  createFastResponse,
  releaseFastResponse,
  debounce,
  throttle,
  LRUCache
};
