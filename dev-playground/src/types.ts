import type { RJSFSchema } from '@rjsf/utils';

export type ChatPluginConfig = {
  enabled?: boolean;
  pluginUrl?: string;
  pluginId?: string;
} | null;

export type MethodRow = {
  identifier: string;
  name: string;
  description?: string;
  inputSchema: RJSFSchema;
  endpoint?: string;
  httpMethod?: string;
  chatPluginConfig?: ChatPluginConfig;
  /** 与 playground-registry / 算子定义一致：为 true 时应在请求中携带 GeniSpace 头 */
  needsGeniSpaceKey?: boolean;
};

export type OperatorLocalesZh = {
  name?: string;
  description?: string;
  methods?: Array<{ identifier: string; name?: string; description?: string }>;
};

export type OperatorRow = {
  id: string;
  identifier: string;
  name: string;
  category: string;
  description?: string;
  methods: MethodRow[];
  /** 来自算子定义 metadata.locales，供中英文切换展示 */
  metadata?: { locales?: { zh?: OperatorLocalesZh } };
};
