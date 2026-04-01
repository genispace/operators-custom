'use strict';

/**
 * 算子 module.exports 字段访问：优先根级（推荐），兼容历史 `genispace` 包裹。
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
