'use strict';

/**
 * GeniSpace API Key 调试/执行约定（与平台 Admin systemConfiguration.enableGeniSpaceAuth、
 * Worker RestApiNodeAdapter 的 GeniSpace 头一致）。
 */

/**
 * 方法级 OpenAPI security 是否声明 GeniSpaceAuth
 * @param {object} rawMethod - 算子源文件中的 method 对象
 * @returns {boolean}
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

/**
 * 算子根级是否启用 GeniSpace 认证（与后台字段名一致）
 * @param {object} config - 算子 module.exports
 * @returns {boolean}
 */
function operatorEnableGeniSpaceAuth(config) {
  return config?.enableGeniSpaceAuth === true;
}

/**
 * 调试台是否应展示 GeniSpace API Key 并在请求中带 GeniSpace 头。
 * 仅认算子根级 enableGeniSpaceAuth（与 Admin systemConfiguration 一致）；
 * 方法级 security: GeniSpaceAuth 只用于 OpenAPI 文档，不单独触发调试台认证区。
 * @param {object} config - 算子 module.exports
 * @returns {boolean}
 */
function playgroundNeedsGeniSpaceKey(config) {
  return operatorEnableGeniSpaceAuth(config);
}

/**
 * @deprecated 使用 {@link playgroundNeedsGeniSpaceKey}；保留签名以免外部误用旧逻辑
 * @param {object} config - 算子 module.exports
 * @param {object} [_rawMethod] - 已忽略
 * @returns {boolean}
 */
function methodNeedsGeniSpaceKey(config, _rawMethod) {
  return playgroundNeedsGeniSpaceKey(config);
}

module.exports = {
  methodSecurityUsesGeniSpaceAuth,
  operatorEnableGeniSpaceAuth,
  playgroundNeedsGeniSpaceKey,
  methodNeedsGeniSpaceKey
};
