// src/patterns/index.ts

export { secretRules } from './secrets';
export { vulnerabilityRules } from './vulnerabilities';
export { hygieneRules } from './hygiene';
export { advancedRules } from './advanced';

import { secretRules } from './secrets';
import { vulnerabilityRules } from './vulnerabilities';
import { hygieneRules } from './hygiene';
import { advancedRules } from './advanced';
import { ScanRule } from '../types';

export const allRules: ScanRule[] = [
  ...secretRules,
  ...vulnerabilityRules,
  ...hygieneRules,
  ...advancedRules,
];