// Hand-maintained declarations for the generated Ajv standalone module
// (explorer contract §4.3). generate-validators.mjs writes validators.js;
// this file only describes its stable exported surface for typechecking.

export interface SchemaValidationError {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  message?: string;
  params: Record<string, unknown>;
}

export interface StandaloneValidateFunction {
  (data: unknown): boolean;
  errors: SchemaValidationError[] | null;
}

export const validateReport: StandaloneValidateFunction;
export const validateExplorerReview: StandaloneValidateFunction;
export const validateExplorerExport: StandaloneValidateFunction;
export const supportedSchemaVersion: string;
export const schemaDialect: string;
