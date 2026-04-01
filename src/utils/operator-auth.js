'use strict';

/**
 * GeniSpace API key conventions (Admin systemConfiguration.enableGeniSpaceAuth,
 * Worker RestApiNodeAdapter GeniSpace header).
 */

/**
 * Whether method OpenAPI security references GeniSpaceAuth.
 */
function methodSecurityUsesGeniSpaceAuth(rawMethod) {
  const sec = rawMethod?.security;
  if (!Array.isArray(sec)) return false;
  return sec.some(
    (item) =>
      item &&
      typeof item === 'object' &&
      Object.prototype.hasOwnProperty.call(item, 'GeniSpaceAuth')
  );
}

/** Root-level GeniSpace auth enabled on operator config. */
function operatorEnableGeniSpaceAuth(config) {
  return config?.enableGeniSpaceAuth === true;
}

/**
 * Playground: show GeniSpace API key field and send GeniSpace header.
 * Only root enableGeniSpaceAuth; method-level security is for OpenAPI only.
 */
function playgroundNeedsGeniSpaceKey(config) {
  return operatorEnableGeniSpaceAuth(config);
}

/** @deprecated Use playgroundNeedsGeniSpaceKey */
function methodNeedsGeniSpaceKey(config, _rawMethod) {
  return playgroundNeedsGeniSpaceKey(config);
}

module.exports = {
  methodSecurityUsesGeniSpaceAuth,
  operatorEnableGeniSpaceAuth,
  playgroundNeedsGeniSpaceKey,
  methodNeedsGeniSpaceKey
};
