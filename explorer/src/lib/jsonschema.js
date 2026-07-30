// Structural JSON Schema validation (explorer contract §5.3, layer 1).
//
// A deliberately small, dependency-free interpreter for exactly the keyword
// subset the exported package schemas use (types, required fields,
// enumerations, scalar bounds, unknown-field rejection, $defs/$ref, anyOf,
// const, pattern, length and item bounds, and the date-time format). Errors
// are reported as bounded structural paths and messages — never by echoing
// the complete offending value (explorer §5.3).

/** Maximum validation errors retained before reporting is cut short. */
export const MAX_SCHEMA_ERRORS = 50;

/** Maximum characters of a structural path retained in one error. */
const MAX_PATH_LENGTH = 200;

const DATE_TIME_PATTERN =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/u;

/**
 * @typedef {{ path: string, message: string }} SchemaError
 */

/**
 * @param {string} path
 * @param {string} message
 * @returns {SchemaError}
 */
function schemaError(path, message) {
  const bounded = path.length > MAX_PATH_LENGTH ? `${path.slice(0, MAX_PATH_LENGTH)}...` : path;
  return { path: bounded, message };
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function typeName(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/**
 * @param {unknown} value
 * @param {string} expected
 * @returns {boolean}
 */
function matchesType(value, expected) {
  switch (expected) {
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      return false;
  }
}

/**
 * @param {unknown} left
 * @param {unknown} right
 * @returns {boolean}
 */
function literalEquals(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Resolve a local `#/$defs/Name` reference against the root schema.
 *
 * @param {string} ref
 * @param {Record<string, unknown>} root
 * @returns {Record<string, unknown> | null}
 */
function resolveRef(ref, root) {
  if (!ref.startsWith('#/')) return null;
  /** @type {unknown} */
  let node = root;
  for (const segment of ref.slice(2).split('/')) {
    if (typeof node !== 'object' || node === null || Array.isArray(node)) return null;
    node = /** @type {Record<string, unknown>} */ (node)[segment.replaceAll('~1', '/').replaceAll('~0', '~')];
  }
  if (typeof node !== 'object' || node === null || Array.isArray(node)) return null;
  return /** @type {Record<string, unknown>} */ (node);
}

/**
 * @param {Record<string, unknown>} schema
 * @param {unknown} value
 * @param {string} path
 * @param {Record<string, unknown>} root
 * @param {SchemaError[]} errors
 * @param {number} depth
 * @returns {void}
 */
function check(schema, value, path, root, errors, depth) {
  if (errors.length >= MAX_SCHEMA_ERRORS) return;
  if (depth > 64) {
    errors.push(schemaError(path, 'value nests too deeply'));
    return;
  }
  const ref = schema.$ref;
  if (typeof ref === 'string') {
    const resolved = resolveRef(ref, root);
    if (resolved === null) {
      errors.push(schemaError(path, `unresolvable schema reference ${ref}`));
      return;
    }
    check(resolved, value, path, root, errors, depth + 1);
    return;
  }
  const anyOf = schema.anyOf;
  if (Array.isArray(anyOf)) {
    for (const option of anyOf) {
      /** @type {SchemaError[]} */
      const optionErrors = [];
      check(/** @type {Record<string, unknown>} */ (option), value, path, root, optionErrors, depth + 1);
      if (optionErrors.length === 0) return;
    }
    errors.push(schemaError(path, 'value matches no allowed alternative'));
    return;
  }
  if ('const' in schema && !literalEquals(value, schema.const)) {
    errors.push(schemaError(path, `value is not the required constant ${JSON.stringify(schema.const)}`));
    return;
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => literalEquals(value, candidate))) {
    errors.push(schemaError(path, 'value is not one of the allowed enumeration values'));
    return;
  }
  const expectedType = schema.type;
  if (typeof expectedType === 'string' && !matchesType(value, expectedType)) {
    errors.push(schemaError(path, `expected ${expectedType}, got ${typeName(value)}`));
    return;
  }
  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) {
      errors.push(schemaError(path, `value is below the minimum ${schema.minimum}`));
    }
    if (typeof schema.maximum === 'number' && value > schema.maximum) {
      errors.push(schemaError(path, `value is above the maximum ${schema.maximum}`));
    }
  }
  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) {
      errors.push(schemaError(path, `string is shorter than ${schema.minLength}`));
    }
    if (typeof schema.maxLength === 'number' && [...value].length > schema.maxLength) {
      errors.push(schemaError(path, `string is longer than ${schema.maxLength}`));
    }
    if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern, 'u').test(value)) {
      errors.push(schemaError(path, 'string does not match the required pattern'));
    }
    if (schema.format === 'date-time' && !DATE_TIME_PATTERN.test(value)) {
      errors.push(schemaError(path, 'string is not an RFC 3339 date-time'));
    }
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) {
      errors.push(schemaError(path, `array has fewer than ${schema.minItems} item(s)`));
    }
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) {
      errors.push(schemaError(path, `array has more than ${schema.maxItems} item(s)`));
    }
    const items = schema.items;
    if (typeof items === 'object' && items !== null && !Array.isArray(items)) {
      for (let index = 0; index < value.length; index += 1) {
        if (errors.length >= MAX_SCHEMA_ERRORS) return;
        check(/** @type {Record<string, unknown>} */ (items), value[index], `${path}[${index}]`, root, errors, depth + 1);
      }
    }
  }
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const record = /** @type {Record<string, unknown>} */ (value);
    const properties =
      typeof schema.properties === 'object' && schema.properties !== null && !Array.isArray(schema.properties)
        ? /** @type {Record<string, unknown>} */ (schema.properties)
        : {};
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) {
        if (typeof name === 'string' && !(name in record)) {
          errors.push(schemaError(path, `missing required field ${JSON.stringify(name)}`));
        }
      }
    }
    if (schema.additionalProperties === false) {
      for (const name of Object.keys(record)) {
        if (!(name in properties)) {
          errors.push(schemaError(path, `unknown field ${JSON.stringify(name)}`));
        }
      }
    }
    for (const [name, subschema] of Object.entries(properties)) {
      if (errors.length >= MAX_SCHEMA_ERRORS) return;
      if (name in record) {
        check(
          /** @type {Record<string, unknown>} */ (subschema),
          record[name],
          `${path}.${name}`,
          root,
          errors,
          depth + 1,
        );
      }
    }
  }
}

/**
 * Validate one value against an exported package schema.
 *
 * @param {Record<string, unknown>} schema Root schema document.
 * @param {unknown} value Parsed JSON value.
 * @returns {SchemaError[]} Bounded structural errors; empty when valid.
 */
export function validateAgainstSchema(schema, value) {
  /** @type {SchemaError[]} */
  const errors = [];
  check(schema, value, '$', schema, errors, 0);
  return errors;
}
