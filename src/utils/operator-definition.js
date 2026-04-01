'use strict';

/**
 * Operator module.exports helpers: prefer root fields, fall back to legacy `genispace` wrapper.
 */

function operatorMethods(config) {
  const m = config?.methods ?? config?.genispace?.methods;
  return Array.isArray(m) ? m : [];
}

function openapiComponentsForDerive(config) {
  return config?.openapiComponents ?? config?.genispace?.openapiComponents;
}

function chatPluginByMethodMap(config) {
  return config?.chatPluginByMethod ?? config?.genispace?.chatPluginByMethod ?? {};
}

module.exports = {
  operatorMethods,
  openapiComponentsForDerive,
  chatPluginByMethodMap
};
